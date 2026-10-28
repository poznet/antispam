<?php

namespace AntispamBundle\Services\Doctor;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\CronRun;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\User;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\Backup\AppVersion;
use AntispamBundle\Services\ClamavService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\Database\DatabaseUpgrader;
use AntispamBundle\Services\RuleOwnership;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Configuration sanity checks behind `antispam:doctor`: is this install set up
 * the way production needs it (secrets, mail, https, schema, cron, accounts,
 * rules, optional services, PHP, filesystem)? It reads configuration and does
 * at most a ClamAV PING; runtime monitoring (queues, error rates, alerting)
 * belongs to the health checks, not here.
 *
 * Every check returns a DoctorCheck; an exception inside a check (e.g. the
 * database is down) becomes a FAIL of that check, the others still run.
 */
class DoctorService
{
    public const DEFAULT_APP_SECRET = 'ChangeMeInProductionPlease';
    public const MIN_SECRET_LENGTH = 16;
    public const REQUIRED_EXTENSIONS = ['imap', 'mbstring', 'intl', 'curl', 'sodium', 'pdo_mysql'];
    public const OPTIONAL_EXTENSIONS = ['zip' => 'ZIP backups (antispam:export --output=*.zip)'];
    /** Cron log entries older than this mean the scheduler / crontab stopped. */
    public const CRON_STALE_MINUTES = 60;
    public const DISK_FAIL_BYTES = 100 * 1024 * 1024;
    public const DISK_WARN_BYTES = 1024 * 1024 * 1024;

    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
        private CryptoService $crypto,
        private ClamavService $clamav,
        private AppVersion $version,
        #[Autowire('%env(default::APP_SECRET)%')] private ?string $appSecret,
        #[Autowire('%env(default::MAILER_DSN)%')] private ?string $mailerDsn,
        #[Autowire('%env(default::SYMFONY_TRUSTED_PROXIES)%')] private ?string $trustedProxies,
        #[Autowire('%env(default::ADMIN_PASSWORD_HASH)%')] private ?string $adminPasswordHash,
        #[Autowire('%kernel.environment%')] private string $environment,
        #[Autowire('%session.storage.options%')] private array $sessionOptions,
        #[Autowire('%kernel.project_dir%')] private string $projectDir,
        #[Autowire('%antispam.ssh_keys_dir%')] private string $sshKeysDir,
        private DatabaseUpgrader $upgrader,
        private ?\AntispamBundle\Services\Bayes\BayesService $bayes = null,
    ) {
    }

    /** @return DoctorCheck[] */
    public function run(): array
    {
        $checks = [];
        $dbUp = true;
        // id => [check, needs the database]
        foreach ([
            'version' => [fn() => $this->checkVersion(), false],
            'app_secret' => [fn() => $this->checkAppSecret(), false],
            'encryption' => [fn() => $this->checkEncryption(), false],
            'php_extensions' => [fn() => $this->checkExtensions(), false],
            'var_writable' => [fn() => $this->checkWritable(), false],
            'disk_space' => [fn() => $this->checkDiskSpace(), false],
            'https' => [fn() => $this->checkHttps(), false],
            'database' => [fn() => $this->checkDatabase(), false],
            'schema' => [fn() => $this->checkSchema(), true],
            'admin_login' => [fn() => $this->checkAdminLogin(), true],
            'mailer' => [fn() => $this->checkMailer(), true],
            'public_url' => [fn() => $this->checkPublicUrls(), true],
            'cron' => [fn() => $this->checkCron(), true],
            'accounts_scanned' => [fn() => $this->checkAccountsScanned(), true],
            'ssh_agents' => [fn() => $this->checkSshAgents(), true],
            'stored_passwords' => [fn() => $this->checkStoredPasswords(), true],
            'orphan_rules' => [fn() => $this->checkOrphanRules(), true],
            'feed' => [fn() => $this->checkFeed(), true],
            'clamav' => [fn() => $this->checkClamav(), true],
            'bayes' => [fn() => $this->checkBayes(), true],
        ] as $id => [$check, $needsDb]) {
            if ($needsDb && !$dbUp) {
                $checks[] = DoctorCheck::skip($id, 'Skipped - the database is not reachable.');
                continue;
            }
            try {
                $result = $check();
            } catch (\Throwable $e) {
                $result = DoctorCheck::fail($id, 'Check failed: ' . self::oneLine($e->getMessage()));
            }
            if ($id === 'database' && $result->status === DoctorCheck::FAIL) {
                $dbUp = false;
            }
            $checks[] = $result;
        }

        return $checks;
    }

    private function checkDatabase(): DoctorCheck
    {
        try {
            $this->pingDatabase();
        } catch (\Throwable $e) {
            return DoctorCheck::fail('database', 'Database not reachable: ' . self::oneLine($e->getMessage()),
                'Check DATABASE_HOST / DATABASE_USER / DATABASE_PASSWORD and that the db service is running.');
        }

        return DoctorCheck::ok('database', 'Database connection works.');
    }

    protected function pingDatabase(): void
    {
        $this->em->getConnection()->executeQuery('SELECT 1')->fetchOne();
    }

    // ---- secrets / login -------------------------------------------------------

    private function checkVersion(): DoctorCheck
    {
        $version = $this->version->get();

        return DoctorCheck::ok('version', 'Application version: ' . ($version ?? 'unknown') . ', PHP ' . PHP_VERSION . ', environment ' . $this->environment . '.');
    }

    private function checkAppSecret(): DoctorCheck
    {
        $secret = (string)$this->appSecret;
        if ($secret === '' || $secret === self::DEFAULT_APP_SECRET) {
            return DoctorCheck::fail('app_secret', 'APP_SECRET is empty or the default value.',
                'Set a random value: php -r \'echo bin2hex(random_bytes(32));\' (changing it later makes stored passwords and digest links invalid).');
        }
        if (strlen($secret) < self::MIN_SECRET_LENGTH) {
            return DoctorCheck::fail('app_secret', sprintf('APP_SECRET is only %d characters long (minimum %d).', strlen($secret), self::MIN_SECRET_LENGTH),
                'Use 32+ random characters, e.g. bin2hex(random_bytes(32)).');
        }
        if (count(array_unique(str_split($secret))) < 6) {
            return DoctorCheck::warn('app_secret', 'APP_SECRET has very few distinct characters - it does not look random.', 'Use bin2hex(random_bytes(32)).');
        }

        return DoctorCheck::ok('app_secret', sprintf('APP_SECRET is set (%d characters).', strlen($secret)));
    }

    private function checkEncryption(): DoctorCheck
    {
        if (!$this->extensionLoaded('sodium')) {
            return DoctorCheck::fail('encryption', 'The sodium extension is missing - stored passwords cannot be encrypted or read.', 'Install / enable ext-sodium.');
        }
        $probe = 'doctor-' . bin2hex(random_bytes(4));
        if ($this->crypto->decrypt($this->crypto->encrypt($probe)) !== $probe) {
            return DoctorCheck::fail('encryption', 'The encryption key (derived from APP_SECRET) does not round-trip.');
        }

        return DoctorCheck::ok('encryption', 'Encryption key for stored secrets is available (derived from APP_SECRET).');
    }

    private function checkAdminLogin(): DoctorCheck
    {
        if (trim((string)$this->adminPasswordHash) !== '') {
            return DoctorCheck::ok('admin_login', 'The ADMIN_USER administrator can log in (ADMIN_PASSWORD_HASH is set).');
        }
        $admins = (int)$this->em->createQuery('SELECT COUNT(u.id) FROM ' . User::class . ' u WHERE u.role = :role')
            ->setParameter('role', User::ROLE_ADMIN)->getSingleScalarResult();
        if ($admins === 0) {
            return DoctorCheck::fail('admin_login', 'Nobody can log in as administrator: ADMIN_PASSWORD_HASH is empty and there is no ROLE_ADMIN user.',
                'Set ADMIN_PASSWORD (Docker) or ADMIN_PASSWORD_HASH (php bin/console security:hash-password).');
        }

        return DoctorCheck::ok('admin_login', sprintf('ADMIN_PASSWORD_HASH is empty, %d database administrator(s) can log in.', $admins));
    }

    // ---- mail / https / URLs -------------------------------------------------------

    private function checkMailer(): DoctorCheck
    {
        $needs = [];
        if ($this->flag('digest.enabled')) {
            $needs[] = 'quarantine digest';
        }
        // Health alerts (Stan systemu): on unless switched off, and they go by
        // e-mail when a recipient is set or the digest address is used instead.
        $alertsOn = $this->config->get('health.alert_enabled') === null || $this->flag('health.alert_enabled');
        $alertRecipient = trim((string)$this->config->get('health.alert_email')) !== '' || trim((string)$this->config->get('digest.from_email')) !== '';
        if ($alertsOn && $alertRecipient) {
            $needs[] = 'e-mail alerts (Stan systemu)';
        }
        $dsn = trim((string)$this->mailerDsn);
        $disabled = $dsn === '' || str_starts_with(strtolower($dsn), 'null://');
        if (!$needs) {
            return $disabled
                ? DoctorCheck::ok('mailer', 'MAILER_DSN is not set - fine, nothing sends e-mail (digest and alerts are off).')
                : DoctorCheck::ok('mailer', 'MAILER_DSN is set.');
        }
        if ($disabled) {
            return DoctorCheck::fail('mailer', 'MAILER_DSN is empty or null:// but ' . implode(' and ', $needs) . ' is enabled - no e-mail will be sent.',
                'Set MAILER_DSN, e.g. smtp://user:pass@smtp.example.com:587.');
        }

        return DoctorCheck::ok('mailer', 'MAILER_DSN is set for ' . implode(' and ', $needs) . '.');
    }

    private function checkHttps(): DoctorCheck
    {
        if ($this->environment !== 'prod') {
            return DoctorCheck::skip('https', 'Not the prod environment (' . $this->environment . ') - https / proxy checks skipped.');
        }
        if (($this->sessionOptions['cookie_secure'] ?? null) !== true) {
            return DoctorCheck::fail('https', 'The session cookie is not always Secure in prod (framework.session.cookie_secure).',
                'Keep cookie_secure: true under when@prod in config/packages/framework.yaml.');
        }
        if (trim((string)$this->trustedProxies) === '') {
            return DoctorCheck::warn('https', 'SYMFONY_TRUSTED_PROXIES is empty: behind a TLS proxy Symfony sees http:// and the proxy IP (no HSTS, login throttling per proxy, http:// links).',
                'Set SYMFONY_TRUSTED_PROXIES to the proxy address(es); check with: curl -sI https://<host>/ | grep -i strict-transport');
        }

        return DoctorCheck::ok('https', 'Session cookie is Secure; trusted proxies: ' . trim((string)$this->trustedProxies) . '.');
    }

    private function checkPublicUrls(): DoctorCheck
    {
        $problems = [];
        $pluginEnabled = $this->config->get('plugin.enabled') === null || $this->flag('plugin.enabled');
        $public = rtrim(trim((string)$this->config->get('plugin.public_url')), '/');
        if ($public !== '') {
            $scheme = strtolower((string)parse_url($public, PHP_URL_SCHEME));
            if ($scheme !== 'https') {
                $problems[] = 'plugin.public_url (' . $public . ') is not https - Outlook refuses the add-in and plugin logins travel in clear text';
            }
            $host = strtolower((string)parse_url($public, PHP_URL_HOST));
            if (in_array($host, ['localhost', '127.0.0.1', '::1'], true) || str_ends_with($host, '.local')) {
                $problems[] = 'plugin.public_url points to a local host (' . $host . ') - downloaded plugins cannot reach it';
            }
        } elseif ($pluginEnabled) {
            $problems[] = 'plugin.public_url is empty - plugins get the address of whatever host served the download';
        }
        if ($this->flag('digest.enabled')) {
            $base = trim((string)$this->config->get('digest.base_url'));
            if ($base !== '' && strtolower((string)parse_url($base, PHP_URL_SCHEME)) !== 'https') {
                $problems[] = 'digest.base_url (' . $base . ') is not https - quarantine links would be sent over http';
            }
        }
        if ($problems) {
            return DoctorCheck::warn('public_url', implode('; ', $problems) . '.',
                'Set https://<your domain> under Ustawienia → Wtyczki pocztowe (and Raport kwarantanny).');
        }

        return DoctorCheck::ok('public_url', $public !== '' ? 'Public URL ' . $public . ' is https.' : 'Mail client plugins are disabled.');
    }

    // ---- database ----------------------------------------------------------------

    private function checkSchema(): DoctorCheck
    {
        $pending = $this->pendingMigrations();
        if ($pending) {
            return DoctorCheck::fail('schema', sprintf('%d database migration(s) not executed yet (%s).', count($pending), implode(', ', array_map(fn($v) => preg_replace('/^.*\\\\/', '', $v), $pending))),
                'Run php bin/console antispam:db:upgrade (the Docker entrypoint does it at boot unless RUN_MIGRATIONS=false).');
        }
        $sql = $this->schemaDiff();
        if ($sql) {
            return DoctorCheck::warn('schema', sprintf('All migrations are executed, but the entities differ from the database (%d statement(s), e.g. %s) - an entity change has no migration.', count($sql), self::oneLine(mb_substr($sql[0], 0, 120))),
                'Generate and commit a migration: php bin/console doctrine:migrations:diff (docs/migrations.md).');
        }

        return DoctorCheck::ok('schema', 'All database migrations are executed and the schema matches the entities.');
    }

    /** @return string[] migration versions not executed yet */
    protected function pendingMigrations(): array
    {
        return $this->upgrader->pendingMigrations();
    }

    /** @return string[] non-DROP SQL that `doctrine:schema:update` would still run */
    protected function schemaDiff(): array
    {
        return $this->upgrader->pendingSchemaChanges();
    }


    private function checkCron(): DoctorCheck
    {
        $last = $this->em->getRepository(CronRun::class)->findOneBy([], ['startedAt' => 'DESC']);
        if ($last === null) {
            return DoctorCheck::warn('cron', 'No job was ever recorded in the cron log - nothing scans the mailboxes automatically.',
                'Use docker-compose.prod.yml (scheduler service) or a crontab entry: php bin/console antispam:cron:run antispam:agent:scan-all');
        }
        $age = (int)floor((time() - $last->getStartedAt()->getTimestamp()) / 60);
        if ($age > self::CRON_STALE_MINUTES) {
            return DoctorCheck::warn('cron', sprintf('The last job in the cron log (%s) started %d minutes ago - the scheduler / crontab seems to have stopped.', $last->getCommand(), $age),
                'Check the scheduler service logs (docker compose logs scheduler) or the host crontab.');
        }

        return DoctorCheck::ok('cron', sprintf('Scheduler is running (last job %s, %d min ago).', $last->getCommand(), $age));
    }

    private function checkAccountsScanned(): DoctorCheck
    {
        $accounts = $this->em->getRepository(Account::class)->findAll();
        if (!$accounts) {
            return DoctorCheck::skip('accounts_scanned', 'No IMAP / SSH accounts configured.');
        }
        $never = [];
        foreach ($accounts as $a) {
            if ($a->getLastScanAt() === null) {
                $never[] = $a->getEmail();
            }
        }
        if ($never) {
            return DoctorCheck::warn('accounts_scanned', sprintf('%d of %d account(s) never had a successful scan: %s.', count($never), count($accounts), self::listSome($never)),
                'Open Konta → Test / Skanuj for these accounts (SSH: deploy the agent first).');
        }

        return DoctorCheck::ok('accounts_scanned', sprintf('All %d account(s) were scanned successfully at least once.', count($accounts)));
    }

    private function checkSshAgents(): DoctorCheck
    {
        $bundled = $this->bundledAgentVersion();
        $deployed = array_filter($this->em->getRepository(Account::class)->findAll(), fn(Account $a) => $a->isSsh() && $a->getAgentDeployed());
        if (!$deployed) {
            return DoctorCheck::skip('ssh_agents', 'No deployed SSH agents.');
        }
        if ($bundled === null) {
            return DoctorCheck::skip('ssh_agents', 'Bundled agent version unknown - cannot compare.');
        }
        $old = [];
        $unknown = 0;
        foreach ($deployed as $a) {
            $version = $a->getLastScanResultDecoded()['agent_version'] ?? null;
            if (!is_string($version) || $version === '') {
                $unknown++;
            } elseif (version_compare($version, $bundled, '<')) {
                $old[] = $a->getEmail() . ' (' . $version . ')';
            }
        }
        if ($old) {
            return DoctorCheck::warn('ssh_agents', sprintf('%d SSH agent(s) older than the bundled %s: %s.', count($old), $bundled, self::listSome($old)),
                'Redeploy: php bin/console antispam:agent:deploy <accountId>, then antispam:agent:sync <accountId>.');
        }

        return DoctorCheck::ok('ssh_agents', sprintf('%d deployed SSH agent(s) run the bundled version %s%s.', count($deployed) - $unknown, $bundled,
            $unknown ? sprintf(' (%d without a recorded version yet)', $unknown) : ''));
    }

    protected function bundledAgentVersion(): ?string
    {
        return SshService::bundledAgentVersion();
    }

    private function checkStoredPasswords(): DoctorCheck
    {
        $plain = [];
        $broken = [];
        $legacy = (string)$this->config->get('password');
        if ($legacy !== '') {
            $this->classifySecret($legacy, 'legacy mailbox (Konfiguracja (stara))', $plain, $broken);
        }
        foreach ($this->em->getRepository(Account::class)->findAll() as $a) {
            if ((string)$a->getImapPassword() !== '') {
                $this->classifySecret((string)$a->getImapPassword(), $a->getEmail(), $plain, $broken);
            }
        }
        if ($broken) {
            return DoctorCheck::fail('stored_passwords', 'Stored IMAP password(s) cannot be decrypted (APP_SECRET was changed?): ' . self::listSome($broken) . '.',
                'Enter these passwords again in the panel, or restore the previous APP_SECRET.');
        }
        if ($plain) {
            return DoctorCheck::warn('stored_passwords', 'IMAP password(s) still stored in plain text: ' . self::listSome($plain) . '.',
                'Open the account (or Konfiguracja (stara)), type the password once and save - it is then stored encrypted.');
        }

        return DoctorCheck::ok('stored_passwords', 'All stored IMAP passwords are encrypted.');
    }

    private function classifySecret(string $value, string $label, array &$plain, array &$broken): void
    {
        if (!$this->crypto->isEncrypted($value)) {
            $plain[] = $label;
            return;
        }
        try {
            $this->crypto->decrypt($value);
        } catch (\RuntimeException) {
            $broken[] = $label;
        }
    }

    private function checkOrphanRules(): DoctorCheck
    {
        $known = [RuleOwnership::ALL => true];
        $legacy = strtolower(trim((string)$this->config->get('email')));
        if ($legacy !== '') {
            $known[$legacy] = true;
        }
        foreach ($this->em->getRepository(Account::class)->findAll() as $a) {
            $known[strtolower(trim((string)$a->getEmail()))] = true;
        }
        $orphans = [];
        foreach ([Blacklist::class, Whitelist::class, EmailBlacklist::class, EmailWhitelist::class] as $entity) {
            $rows = $this->em->createQuery('SELECT r.email AS owner, COUNT(r.id) AS n FROM ' . $entity . ' r GROUP BY r.email')->getArrayResult();
            foreach ($rows as $row) {
                $owner = strtolower(trim((string)$row['owner']));
                if (!isset($known[$owner])) {
                    $orphans[$owner === '' ? '(empty)' : $owner] = ($orphans[$owner === '' ? '(empty)' : $owner] ?? 0) + (int)$row['n'];
                }
            }
        }
        if ($orphans) {
            $list = array_map(fn($o, $n) => $o . ': ' . $n, array_keys($orphans), $orphans);
            return DoctorCheck::warn('orphan_rules', sprintf('%d rule(s) belong to mailboxes that no longer exist - they never match: %s.', array_sum($orphans), self::listSome($list)),
                'Delete them, or make them global: php bin/console antispam:rules:make-global --owner=<address>.');
        }

        return DoctorCheck::ok('orphan_rules', 'Every list rule belongs to an existing mailbox or to all mailboxes.');
    }

    // ---- optional services -------------------------------------------------------

    private function checkFeed(): DoctorCheck
    {
        if (!$this->flag('feed.enabled')) {
            return DoctorCheck::skip('feed', 'Shared spam feed is disabled.');
        }
        $remoteUrl = trim((string)$this->config->get('feed.remote_url'));
        $remoteKey = trim((string)$this->config->get('feed.remote_key'));
        $serverKey = trim((string)$this->config->get('feed.server_key'));
        if ($remoteUrl !== '' && $remoteKey === '') {
            return DoctorCheck::fail('feed', 'Shared feed hub URL is set but its key (feed.remote_key) is empty - every sync is rejected.',
                'Enter the hub key under Ustawienia → Wspólna baza spamu.');
        }
        if ($remoteUrl !== '' && strtolower((string)parse_url($remoteUrl, PHP_URL_SCHEME)) !== 'https') {
            return DoctorCheck::warn('feed', 'Shared feed hub URL (' . $remoteUrl . ') is not https - the key travels in clear text.', 'Use an https:// hub URL.');
        }
        if ($remoteUrl === '' && $serverKey === '') {
            return DoctorCheck::warn('feed', 'Shared feed is enabled but neither a hub (remote URL + key) nor a local API key is set - nothing is shared.',
                'Configure Ustawienia → Wspólna baza spamu, or disable the feed.');
        }
        if ($serverKey !== '' && strlen($serverKey) < 16) {
            return DoctorCheck::warn('feed', 'The local feed API key (feed.server_key) is shorter than 16 characters.', 'Use a long random key.');
        }

        return DoctorCheck::ok('feed', 'Shared feed keys are set' . ($remoteUrl !== '' ? ' (hub ' . $remoteUrl . ')' : '') . '.');
    }

    /** Bayes classifier: stats only (docs/bayes.md). */
    private function checkBayes(): DoctorCheck
    {
        if (!$this->bayes || !$this->bayes->isEnabled()) {
            return DoctorCheck::skip('bayes', 'Bayes classifier is disabled.');
        }
        $s = $this->bayes->stats();
        $msg = sprintf('Bayes classifier: %d spam / %d ham messages learned, %d tokens (global)', $s['spam'], $s['ham'], $s['tokens']);
        if (!$s['ready']) {
            return DoctorCheck::warn('bayes', $msg . sprintf(' - not scoring until %d spam and %d ham are learned.', $s['min_spam'], $s['min_ham']),
                'Train it: php bin/console antispam:bayes:train --account=<mailbox> --folder=SPAM --ham-folder=INBOX, or let users report spam / not spam.');
        }

        return DoctorCheck::ok('bayes', $msg . '.');
    }

    private function checkClamav(): DoctorCheck
    {
        if (!$this->flag('scoring.clamav_enabled')) {
            return DoctorCheck::skip('clamav', 'ClamAV scanning is disabled.');
        }
        $dsn = (string)($this->config->get('scoring.clamav_dsn') ?: ScoringService::DEFAULT_CLAMAV_DSN);
        $timeout = min(5, (int)($this->config->get('scoring.clamav_timeout') ?: 5));
        if (!$this->clamav->ping($dsn, max(1, $timeout))) {
            return DoctorCheck::fail('clamav', 'ClamAV is enabled but clamd does not answer at ' . $dsn . ' - attachments are not scanned.',
                'Start the clamav service (Docker: tcp://clamav:3310) or fix the address under Ustawienia → Filtr spamu.');
        }

        return DoctorCheck::ok('clamav', 'clamd answers at ' . $dsn . '.');
    }

    // ---- PHP / filesystem ----------------------------------------------------------

    private function checkExtensions(): DoctorCheck
    {
        $missing = array_values(array_filter(self::REQUIRED_EXTENSIONS, fn($ext) => !$this->extensionLoaded($ext)));
        if ($missing) {
            return DoctorCheck::fail('php_extensions', 'Missing PHP extension(s): ' . implode(', ', $missing) . '.', 'Install them (the Docker image has them all).');
        }
        $optional = [];
        foreach (self::OPTIONAL_EXTENSIONS as $ext => $usage) {
            if (!$this->extensionLoaded($ext)) {
                $optional[] = $ext . ' (' . $usage . ')';
            }
        }
        if ($optional) {
            return DoctorCheck::warn('php_extensions', 'Optional PHP extension(s) missing: ' . implode(', ', $optional) . '.');
        }

        return DoctorCheck::ok('php_extensions', 'PHP extensions present: ' . implode(', ', array_merge(self::REQUIRED_EXTENSIONS, array_keys(self::OPTIONAL_EXTENSIONS))) . '.');
    }

    protected function extensionLoaded(string $ext): bool
    {
        return extension_loaded($ext);
    }

    private function checkWritable(): DoctorCheck
    {
        $bad = [];
        foreach (['var', 'var/cache', 'var/log', 'var/data'] as $dir) {
            $path = $this->projectDir . '/' . $dir;
            if (!$this->isWritableDir($path)) {
                $bad[] = $dir;
            }
        }
        if ($bad) {
            return DoctorCheck::fail('var_writable', 'Not writable (or missing): ' . implode(', ', $bad) . '.', 'chown -R www-data:www-data var/ (the Docker entrypoint does it at boot).');
        }
        $keys = $this->sshKeysDir;
        if (is_dir($keys) && (fileperms($keys) & 0o077) !== 0) {
            return DoctorCheck::warn('var_writable', 'var/ is writable, but the SSH keys directory ' . $keys . ' is readable by other users.', 'chmod 700 ' . $keys);
        }

        return DoctorCheck::ok('var_writable', 'var/, var/cache, var/log and var/data are writable.');
    }

    protected function isWritableDir(string $path): bool
    {
        return is_dir($path) && is_writable($path);
    }

    private function checkDiskSpace(): DoctorCheck
    {
        $dir = is_dir($this->projectDir . '/var/data') ? $this->projectDir . '/var/data' : $this->projectDir;
        $free = $this->freeSpace($dir);
        if ($free === null) {
            return DoctorCheck::skip('disk_space', 'Free disk space cannot be determined.');
        }
        $human = sprintf('%.1f GB', $free / 1073741824);
        if ($free < self::DISK_FAIL_BYTES) {
            return DoctorCheck::fail('disk_space', 'Only ' . $human . ' free on the var/data volume.', 'Free disk space (logs, old backups) - the database and the quarantine stop growing when it runs out.');
        }
        if ($free < self::DISK_WARN_BYTES) {
            return DoctorCheck::warn('disk_space', 'Only ' . $human . ' free on the var/data volume.', 'Plan more disk space.');
        }

        return DoctorCheck::ok('disk_space', $human . ' free on the var/data volume.');
    }

    protected function freeSpace(string $dir): ?float
    {
        $free = @disk_free_space($dir);

        return $free === false ? null : (float)$free;
    }

    // ---- helpers ---------------------------------------------------------------

    private function flag(string $key): bool
    {
        $v = $this->config->get($key);

        return $v === true || in_array(strtolower(trim((string)$v)), ['1', 'true', 'yes', 'on'], true);
    }

    private static function listSome(array $items, int $max = 10): string
    {
        $shown = array_slice($items, 0, $max);

        return implode(', ', $shown) . (count($items) > $max ? sprintf(' and %d more', count($items) - $max) : '');
    }

    private static function oneLine(string $text): string
    {
        return trim(preg_replace('/\s+/', ' ', $text));
    }
}
