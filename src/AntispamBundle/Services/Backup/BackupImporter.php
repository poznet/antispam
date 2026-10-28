<?php

namespace AntispamBundle\Services\Backup;

use AntispamBundle\Controller\AccountController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Config;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\ListSetting;
use AntispamBundle\Entity\User;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\ImapFlags;
use AntispamBundle\Services\PatternMatcher;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Restores a configuration backup (BackupFormat) into this instance.
 *
 * Records are matched by natural keys, never by id: setting name, rule list +
 * owner + pattern type + value, DNSBL zone, account e-mail, username.
 *
 *  - merge (default): create missing records, update changed ones, keep
 *    everything that is not in the file;
 *  - replace: like merge, then delete the records of the imported sections
 *    that are not in the file. Matching records are updated in place, so the
 *    ids (and with them quarantine keys `imap-<id>` / `ssh-<id>`, last-sent
 *    markers) of surviving accounts are kept.
 *
 * Both run in one transaction (all or nothing); a dry run only plans and
 * writes nothing. Secrets are never overwritten with an empty value, never
 * deleted (also not in replace mode) and only used when the file was
 * exported with secrets by an instance with the same APP_SECRET (checked
 * with `secrets.key_check`); otherwise they are skipped with a warning.
 */
class BackupImporter
{
    public const MODE_MERGE = 'merge';
    public const MODE_REPLACE = 'replace';
    public const MODES = [self::MODE_MERGE, self::MODE_REPLACE];

    private const PATTERN_TYPES = ['exact', 'wildcard', 'regex'];
    /** Settings that end up in URLs, plugin manifests or HTTP requests: plain http(s) base URL only. */
    private const URL_SETTINGS = ['plugin.public_url', 'digest.base_url', 'feed.remote_url', 'cert.url'];

    private ImportReport $report;
    private bool $dry = true;
    private bool $secretsUsable = false;
    /** @var array<string, Account|null> lower(e-mail) => account (null = will be created by this dry run) */
    private array $accountsByEmail = [];

    public function __construct(
        private EntityManagerInterface $em,
        private CryptoService $crypto,
        #[Autowire('%env(default::ADMIN_USER)%')] private string $envAdminUser = '',
    ) {
    }

    /**
     * @param string[] $sections subset of BackupFormat::SECTIONS
     * @param string|null $protectUsername user that replace mode must not delete (the admin running the import)
     */
    public function import(array $data, array $sections, string $mode = self::MODE_MERGE, bool $dryRun = false, ?string $protectUsername = null): ImportReport
    {
        if (!in_array($mode, self::MODES, true)) {
            throw new InvalidBackupException('Unknown import mode "' . $mode . '" (merge or replace).');
        }
        $sections = array_values(array_intersect(BackupFormat::SECTIONS, $sections));
        $this->report = new ImportReport($mode, $dryRun, $sections, [
            'schema_version' => $data['schema_version'] ?? null,
            'app_version' => $data['app_version'] ?? null,
            'exported_at' => $data['exported_at'] ?? null,
            'include_secrets' => !empty($data['include_secrets']),
        ]);
        $this->dry = $dryRun;
        $this->secretsUsable = $this->checkSecrets($data);

        $run = function () use ($data, $sections, $mode, $protectUsername) {
            $replace = $mode === self::MODE_REPLACE;
            $this->loadAccounts();
            foreach ($sections as $section) {
                if (!isset($data[$section])) {
                    $this->report->warn('Section "' . $section . '" is not in the file - left as it is.');
                }
            }
            if (in_array('settings', $sections, true) && isset($data['settings'])) {
                $this->importSettings($data['settings'], $replace);
            }
            if (in_array('rules', $sections, true) && isset($data['rules'])) {
                $this->importRules($data['rules'], $replace);
            }
            if (in_array('dnsbl', $sections, true) && isset($data['dnsbl'])) {
                $this->importDnsbl($data['dnsbl'], $replace);
            }
            if (in_array('accounts', $sections, true) && isset($data['accounts'])) {
                $this->importAccounts($data['accounts'], $replace);
            }
            if (in_array('users', $sections, true) && isset($data['users'])) {
                $this->importUsers($data['users'], $replace, $protectUsername);
            }
            if (!$this->dry) {
                $this->em->flush();
            }
        };

        if ($dryRun) {
            $run();
        } else {
            $this->em->wrapInTransaction($run);
        }

        return $this->report;
    }

    // ---- secrets -----------------------------------------------------------

    private function checkSecrets(array $data): bool
    {
        if (empty($data['include_secrets'])) {
            return false;
        }
        $check = $data['secrets']['key_check'] ?? null;
        try {
            if (is_string($check) && $this->crypto->isEncrypted($check) && $this->crypto->decrypt($check) === BackupFormat::KEY_CHECK_PLAINTEXT) {
                return true;
            }
        } catch (\RuntimeException) {
            // other key
        }
        $this->report->warn('The secrets in this file were encrypted with another APP_SECRET (or the key check is missing) - '
            . 'all secrets are skipped. To restore them, start this instance with the APP_SECRET of the exporting one, '
            . 'or enter passwords and API keys again after the import.');

        return false;
    }

    /** Plain text of an exported secret, or null (empty, unusable key, damaged value) = keep the current value. */
    private function openSecret($value, string $label): ?string
    {
        if (!$this->secretsUsable || !is_string($value) || $value === '') {
            return null;
        }
        if (!$this->crypto->isEncrypted($value)) {
            $this->report->warn('Secret of ' . $label . ' is not encrypted in the file - skipped.');
            return null;
        }
        try {
            $plain = (string)$this->crypto->decrypt($value);
        } catch (\RuntimeException) {
            $this->report->warn('Secret of ' . $label . ' cannot be decrypted - skipped.');
            return null;
        }

        return $plain === '' ? null : $plain;
    }

    /** Current plain value of a stored secret, null when it cannot be read. */
    private function storedPlain($stored): ?string
    {
        try {
            return (string)$this->crypto->decrypt((string)$stored);
        } catch (\RuntimeException) {
            return null;
        }
    }

    // ---- settings ------------------------------------------------------------

    private function importSettings(array $settings, bool $replace): void
    {
        $rows = [];
        foreach ($this->em->getRepository(Config::class)->findAll() as $row) {
            $rows[(string)$row->getName()] ??= $row;
        }
        $seen = [];

        foreach ($settings['config'] ?? [] as $name => $value) {
            $name = (string)$name;
            if (!preg_match('/^[A-Za-z0-9_.\-]{1,190}$/', $name) || BackupSecrets::isState($name)) {
                $this->skip('settings', 'Setting "' . mb_substr($name, 0, 60) . '" is not importable - skipped.');
                continue;
            }
            if (BackupSecrets::isSecret($name)) {
                $this->skip('settings', 'Setting ' . $name . ' is a secret but not in the encrypted secrets block - skipped.');
                continue;
            }
            if (!is_scalar($value) && $value !== null) {
                $this->skip('settings', 'Setting ' . $name . ' has a non-scalar value - skipped.');
                continue;
            }
            if (in_array($name, self::URL_SETTINGS, true) && !self::isPlainUrl((string)$value)) {
                $this->skip('settings', 'Setting ' . $name . ' is not a plain http(s) URL - skipped.');
                continue;
            }
            $seen[$name] = true;
            $this->upsertConfig($rows, $name, $value, fn($row) => $row->getValue() === $value);
        }

        foreach ($settings['secrets'] ?? [] as $name => $sealed) {
            $name = (string)$name;
            if (!BackupSecrets::isSecret($name)) {
                $this->skip('settings', 'Unknown secret "' . mb_substr($name, 0, 60) . '" - skipped.');
                continue;
            }
            $plain = $this->openSecret($sealed, 'setting ' . $name);
            if ($plain === null) {
                $this->report->count('settings', 'skipped');
                continue;
            }
            $stored = in_array($name, BackupSecrets::STORED_ENCRYPTED, true) ? $this->crypto->encrypt($plain) : $plain;
            $this->upsertConfig($rows, $name, $stored, fn($row) => $this->storedPlain($row->getValue()) === $plain);
        }

        foreach ($rows as $name => $row) {
            // Replace never touches runtime state or secrets.
            if ($replace && !isset($seen[$name]) && !BackupSecrets::isState($name) && !BackupSecrets::isSecret($name)) {
                $this->remove($row, 'settings');
            }
        }

        $lists = [];
        foreach ($this->em->getRepository(ListSetting::class)->findAll() as $row) {
            $lists[strtolower((string)$row->getName())] = $row;
        }
        $seenLists = [];
        foreach ($settings['lists'] ?? [] as $name => $value) {
            $name = (string)$name;
            if (!preg_match('/^[A-Za-z0-9_.\-]{1,128}$/', $name) || (!is_string($value) && $value !== null)) {
                $this->skip('settings', 'List setting "' . mb_substr($name, 0, 60) . '" is invalid - skipped.');
                continue;
            }
            $key = strtolower($name);
            $seenLists[$key] = true;
            $row = $lists[$key] ?? null;
            if ($row === null) {
                $this->persist((new ListSetting())->setName($name)->setValue($value), 'settings');
            } elseif ($row->getValue() === $value) {
                $this->report->count('settings', 'unchanged');
            } else {
                $this->change(fn() => $row->setValue($value), 'settings');
            }
        }
        if ($replace) {
            foreach ($lists as $key => $row) {
                if (!isset($seenLists[$key])) {
                    $this->remove($row, 'settings');
                }
            }
        }
    }

    private function upsertConfig(array &$rows, string $name, $value, callable $isSame): void
    {
        $row = $rows[$name] ?? null;
        if ($row === null) {
            $row = (new Config())->setName($name)->setValue($value);
            $rows[$name] = $row;
            $this->persist($row, 'settings');
        } elseif ($isSame($row)) {
            $this->report->count('settings', 'unchanged');
        } else {
            $this->change(fn() => $row->setValue($value), 'settings');
        }
    }

    // ---- rules ---------------------------------------------------------------

    private function importRules(array $rules, bool $replace): void
    {
        foreach ($rules as $type => $items) {
            if (!isset(BackupExporter::RULE_LISTS[$type])) {
                $this->report->warn('Unknown rule list "' . mb_substr((string)$type, 0, 40) . '" - skipped.');
                continue;
            }
            [$entity, $field, $withScore] = BackupExporter::RULE_LISTS[$type];
            $getter = 'get' . ucfirst($field);
            $setter = 'set' . ucfirst($field);

            $existing = [];
            foreach ($this->em->getRepository($entity)->findAll() as $rule) {
                $existing[self::ruleKey($rule->getEmail(), $rule->getPatternType() ?: 'exact', $rule->$getter())] ??= $rule;
            }
            $seen = [];
            foreach ($items as $i => $item) {
                $label = $type . ' #' . ($i + 1);
                $owner = trim((string)($item['owner'] ?? ''));
                $value = trim((string)($item['value'] ?? ''));
                $patternType = strtolower((string)($item['pattern_type'] ?? 'exact'));
                if ($owner === '' || strlen($owner) > 255 || preg_match('/[\x00-\x1f\x7f]/', $owner)) {
                    $this->skip('rules', $label . ': invalid owner - skipped.');
                    continue;
                }
                if ($value === '' || strlen($value) > 255 || preg_match('/[\x00-\x1f\x7f]/', $value) || !in_array($patternType, self::PATTERN_TYPES, true)) {
                    $this->skip('rules', $label . ': invalid value or pattern type - skipped.');
                    continue;
                }
                if (($error = PatternMatcher::validate($value, $patternType)) !== '') {
                    $this->skip('rules', $label . ' (' . mb_substr($value, 0, 60) . '): ' . $error . ' - skipped.');
                    continue;
                }
                if ($patternType !== 'regex') {
                    $value = strtolower($value);
                }
                $score = max(1, min(1000, (int)($item['score'] ?? 10)));
                $key = self::ruleKey($owner, $patternType, $value);
                if (isset($seen[$key])) {
                    $this->skip('rules', $label . ': duplicate in the file - skipped.');
                    continue;
                }
                $seen[$key] = true;

                $rule = $existing[$key] ?? null;
                if ($rule === null) {
                    $rule = new $entity();
                    $rule->setEmail($owner);
                    $rule->$setter($value);
                    $rule->setPatternType($patternType);
                    $rule->setCounter(max(0, (int)($item['hits'] ?? 0)));
                    if ($withScore) {
                        $rule->setScore($score);
                    }
                    $this->persist($rule, 'rules');
                } elseif ($withScore && (int)$rule->getScore() !== $score) {
                    $this->change(fn() => $rule->setScore($score), 'rules');
                } else {
                    $this->report->count('rules', 'unchanged');
                }
            }
            if ($replace) {
                foreach ($existing as $key => $rule) {
                    if (!isset($seen[$key])) {
                        $this->remove($rule, 'rules');
                    }
                }
            }
        }
    }

    private static function ruleKey($owner, string $patternType, $value): string
    {
        $value = (string)$value;

        return strtolower(trim((string)$owner)) . "\0" . $patternType . "\0" . ($patternType === 'regex' ? $value : strtolower($value));
    }

    // ---- DNSBL -------------------------------------------------------------------

    private function importDnsbl(array $providers, bool $replace): void
    {
        $existing = [];
        foreach ($this->em->getRepository(DnsblProvider::class)->findAll() as $p) {
            $existing[strtolower((string)$p->getZone())] = $p;
        }
        $seen = [];
        foreach ($providers as $i => $item) {
            $zone = strtolower(trim((string)($item['zone'] ?? '')));
            if ($zone === '' || strlen($zone) > 253 || !preg_match('/^[a-z0-9](?:[a-z0-9.\-]*[a-z0-9])?$/', $zone)) {
                $this->skip('dnsbl', 'DNSBL #' . ($i + 1) . ': invalid zone - skipped.');
                continue;
            }
            if (isset($seen[$zone])) {
                $this->skip('dnsbl', 'DNSBL ' . $zone . ': duplicate in the file - skipped.');
                continue;
            }
            $seen[$zone] = true;
            $name = mb_substr(trim((string)($item['name'] ?? '')) ?: $zone, 0, 128);
            $score = max(0, min(1000, (int)($item['score'] ?? 5)));
            $enabled = (bool)($item['enabled'] ?? true);
            $ttl = max(60, (int)($item['cache_ttl'] ?? 3600));

            $p = $existing[$zone] ?? null;
            if ($p === null) {
                $p = (new DnsblProvider())->setZone($zone)->setName($name)->setScore($score)->setEnabled($enabled)
                    ->setCacheTtl($ttl)->setHits(max(0, (int)($item['hits'] ?? 0)));
                $this->persist($p, 'dnsbl');
            } elseif ($p->getName() === $name && (int)$p->getScore() === $score && (bool)$p->isEnabled() === $enabled && (int)$p->getCacheTtl() === $ttl) {
                $this->report->count('dnsbl', 'unchanged');
            } else {
                $this->change(fn() => $p->setName($name)->setScore($score)->setEnabled($enabled)->setCacheTtl($ttl), 'dnsbl');
            }
        }
        if ($replace) {
            foreach ($existing as $zone => $p) {
                if (!isset($seen[$zone])) {
                    $this->remove($p, 'dnsbl');
                }
            }
        }
    }

    // ---- accounts ------------------------------------------------------------

    private function loadAccounts(): void
    {
        $this->accountsByEmail = [];
        foreach ($this->em->getRepository(Account::class)->findAll() as $a) {
            $this->accountsByEmail[strtolower(trim((string)$a->getEmail()))] ??= $a;
        }
    }

    private function importAccounts(array $accounts, bool $replace): void
    {
        $existing = $this->accountsByEmail;
        $seen = [];
        foreach ($accounts as $i => $item) {
            $email = trim((string)($item['email'] ?? ''));
            $key = strtolower($email);
            $type = (string)($item['connection_type'] ?? Account::CONNECTION_IMAP);
            $data = [
                'email' => $email,
                'name' => (string)($item['name'] ?? ''),
                'connection_type' => $type,
                'imap_host' => (string)($item['imap_host'] ?? ''),
                'imap_port' => isset($item['imap_port']) ? (string)$item['imap_port'] : '',
                'imap_login' => (string)($item['imap_login'] ?? ''),
                'ssh_host' => (string)($item['ssh_host'] ?? ''),
                'ssh_port' => isset($item['ssh_port']) ? (string)$item['ssh_port'] : '',
                'ssh_user' => (string)($item['ssh_user'] ?? ''),
                'ssh_key_path' => (string)($item['ssh_key_path'] ?? ''),
                'maildir_path' => (string)($item['maildir_path'] ?? ''),
                'agent_path' => (string)($item['agent_path'] ?? ''),
            ];
            $errors = AccountController::validateAccountData($data);
            if ($errors) {
                $this->skip('accounts', 'Account #' . ($i + 1) . ' (' . mb_substr($email, 0, 80) . '): ' . implode(' ', $errors) . ' - skipped.');
                continue;
            }
            if (isset($seen[$key])) {
                $this->skip('accounts', 'Account ' . $email . ': duplicate in the file - skipped.');
                continue;
            }
            $seen[$key] = true;

            $account = $existing[$key] ?? null;
            $creating = $account === null;
            if ($creating) {
                $account = new Account();
                $account->setAgentDeployed((bool)($item['agent_deployed'] ?? false));
            }

            $fields = [
                'Name' => mb_substr($data['name'], 0, 255),
                'Email' => $email,
                'ConnectionType' => $type,
                'DeleteSpam' => (bool)($item['delete_spam'] ?? false),
                'ImapHost' => self::nullable($item['imap_host'] ?? null),
                'ImapPort' => isset($item['imap_port']) && $item['imap_port'] !== '' ? (int)$item['imap_port'] : 993,
                'ImapLogin' => self::nullable($item['imap_login'] ?? null),
                'ImapFlags' => ImapFlags::sanitize((string)($item['imap_flags'] ?? '/imap/ssl')),
                'SshHost' => self::nullable($item['ssh_host'] ?? null),
                'SshPort' => isset($item['ssh_port']) && $item['ssh_port'] !== '' ? (int)$item['ssh_port'] : 22,
                'SshUser' => self::nullable($item['ssh_user'] ?? null),
                'MaildirPath' => self::nullable($item['maildir_path'] ?? null) ?? '~/Maildir',
                'AgentPath' => self::nullable($item['agent_path'] ?? null) ?? '~/antispam-agent',
            ];
            // Present only in exports with secrets; an empty value keeps the current path.
            if (self::nullable($item['ssh_key_path'] ?? null) !== null) {
                $fields['SshKeyPath'] = (string)$item['ssh_key_path'];
            }
            $hostKey = self::nullable($item['ssh_host_key'] ?? null);
            if ($hostKey !== null && preg_match('/^SHA256:[A-Za-z0-9+\/=]{1,200}$/', $hostKey)) {
                if ((string)$account->getSshHostKey() === '') {
                    $fields['SshHostKey'] = $hostKey;
                } elseif ($account->getSshHostKey() !== $hostKey) {
                    $this->report->warn('Account ' . $email . ': the pinned SSH host key differs from the file - kept the current one.');
                }
            }

            $changes = [];
            foreach ($fields as $prop => $value) {
                if ($creating || $account->{'get' . $prop}() !== $value) {
                    $changes[$prop] = $value;
                }
            }

            $password = $this->openSecret($item['imap_password'] ?? null, 'account ' . $email . ' (IMAP password)');
            if ($password !== null && ($creating || $this->storedPlain($account->getImapPassword()) !== $password)) {
                $changes['ImapPassword'] = $this->crypto->encrypt($password);
            }
            $pluginHash = $this->openSecret($item['plugin_password_hash'] ?? null, 'account ' . $email . ' (plugin password)');
            if ($pluginHash !== null && ($creating || $account->getPluginPasswordHash() !== $pluginHash)) {
                $changes['PluginPasswordHash'] = $pluginHash;
            }

            $apply = function () use ($account, $changes) {
                foreach ($changes as $prop => $value) {
                    $account->{'set' . $prop}($value);
                }
            };
            if ($creating) {
                if (!$this->dry) {
                    $apply();
                }
                $this->persist($account, 'accounts');
                $this->accountsByEmail[$key] = $this->dry ? null : $account;
                if ($type === Account::CONNECTION_IMAP && $password === null) {
                    $this->report->warn('Account ' . $email . ': created without an IMAP password - enter it in the panel.');
                }
            } elseif ($changes) {
                $this->change($apply, 'accounts');
            } else {
                $this->report->count('accounts', 'unchanged');
            }
        }
        if ($replace) {
            foreach ($existing as $key => $account) {
                if (!isset($seen[$key])) {
                    $this->remove($account, 'accounts');
                    unset($this->accountsByEmail[$key]);
                }
            }
        }
    }

    // ---- users ---------------------------------------------------------------

    private function importUsers(array $users, bool $replace, ?string $protectUsername): void
    {
        $existing = [];
        foreach ($this->em->getRepository(User::class)->findAll() as $u) {
            $existing[strtolower((string)$u->getUsername())] = $u;
        }
        $seen = [];
        foreach ($users as $i => $item) {
            $username = trim((string)($item['username'] ?? ''));
            $key = strtolower($username);
            $role = (string)($item['role'] ?? User::ROLE_USER);
            if (strlen($username) < 3 || strlen($username) > 180 || !preg_match('/^[A-Za-z0-9._@+-]+$/', $username)) {
                $this->skip('users', 'User #' . ($i + 1) . ': invalid username - skipped.');
                continue;
            }
            if ($this->envAdminUser !== '' && strcasecmp($username, $this->envAdminUser) === 0) {
                $this->skip('users', 'User ' . $username . ': login reserved for the ADMIN_USER administrator of this server - skipped.');
                continue;
            }
            if (!in_array($role, User::ROLES, true)) {
                $this->skip('users', 'User ' . $username . ': unknown role - skipped.');
                continue;
            }
            if (isset($seen[$key])) {
                $this->skip('users', 'User ' . $username . ': duplicate in the file - skipped.');
                continue;
            }
            $seen[$key] = true;

            // Mailboxes by e-mail: existing accounts and those created by this import.
            $wanted = [];
            $pending = 0;
            foreach ((array)($item['accounts'] ?? []) as $email) {
                $email = strtolower(trim((string)$email));
                if (!array_key_exists($email, $this->accountsByEmail)) {
                    $this->report->warn('User ' . $username . ': mailbox ' . mb_substr($email, 0, 80) . ' does not exist here - not assigned.');
                    continue;
                }
                if ($this->accountsByEmail[$email] === null) {
                    $pending++;
                } else {
                    $wanted[$email] = $this->accountsByEmail[$email];
                }
            }
            if ($role === User::ROLE_USER && !$wanted && !$pending) {
                $this->report->warn('User ' . $username . ' has no mailbox assigned - they will see nothing.');
            }

            $hash = $this->openSecret($item['password_hash'] ?? null, 'user ' . $username);
            if ($hash !== null && !str_starts_with($hash, '$')) {
                $this->report->warn('User ' . $username . ': the password hash is not in a supported format - skipped.');
                $hash = null;
            }

            $user = $existing[$key] ?? null;
            if ($user === null) {
                if ($hash === null) {
                    // Unusable random password: the account exists but cannot log in until an admin sets one.
                    $hash = password_hash(bin2hex(random_bytes(24)), PASSWORD_BCRYPT);
                    $this->report->warn('User ' . $username . ': created without a password - set one under Ustawienia → Użytkownicy.');
                }
                $user = (new User())->setUsername($username)->setRole($role)->setPassword($hash);
                if (!$this->dry) {
                    $user->setAccounts(array_values($wanted));
                }
                $this->persist($user, 'users');
                continue;
            }

            $current = [];
            foreach ($user->getAccounts() as $a) {
                $current[strtolower(trim((string)$a->getEmail()))] = true;
            }
            $sameAccounts = $pending === 0 && !array_diff_key($current, $wanted) && !array_diff_key($wanted, $current);
            $changed = $user->getRole() !== $role || !$sameAccounts || ($hash !== null && $user->getPassword() !== $hash);
            if (!$changed) {
                $this->report->count('users', 'unchanged');
                continue;
            }
            $this->change(function () use ($user, $role, $wanted, $hash) {
                $user->setRole($role);
                $user->setAccounts(array_values($wanted));
                if ($hash !== null) {
                    $user->setPassword($hash);
                }
            }, 'users');
        }
        if ($replace) {
            foreach ($existing as $key => $user) {
                if (isset($seen[$key])) {
                    continue;
                }
                if ($protectUsername !== null && strcasecmp($protectUsername, (string)$user->getUsername()) === 0) {
                    $this->report->warn('User ' . $user->getUsername() . ' is not in the file but runs this import - kept.');
                    continue;
                }
                $this->remove($user, 'users');
            }
        }
    }

    // ---- helpers ---------------------------------------------------------------

    private function persist(object $entity, string $section): void
    {
        if (!$this->dry) {
            $this->em->persist($entity);
        }
        $this->report->count($section, 'created');
    }

    private function change(callable $apply, string $section): void
    {
        if (!$this->dry) {
            $apply();
        }
        $this->report->count($section, 'updated');
    }

    private function remove(object $entity, string $section): void
    {
        if (!$this->dry) {
            $this->em->remove($entity);
        }
        $this->report->count($section, 'deleted');
    }

    private function skip(string $section, string $warning): void
    {
        $this->report->warn($warning);
        $this->report->count($section, 'skipped');
    }

    private static function nullable($value): ?string
    {
        $value = $value === null ? '' : trim((string)$value);

        return $value === '' ? null : $value;
    }

    private static function isPlainUrl(string $url): bool
    {
        if ($url === '') {
            return true;
        }
        $parts = parse_url($url);

        return $parts && in_array($parts['scheme'] ?? '', ['http', 'https'], true) && !empty($parts['host'])
            && !isset($parts['user']) && !isset($parts['pass']) && !isset($parts['fragment'])
            && !preg_match('/[\x00-\x20"\\\\<>]/', $url);
    }
}
