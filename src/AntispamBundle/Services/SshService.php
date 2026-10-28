<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use Doctrine\ORM\EntityManagerInterface;
use phpseclib3\Net\SSH2;
use phpseclib3\Net\SFTP;
use phpseclib3\Crypt\PublicKeyLoader;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Talks to the Maildir agent on a hosting server over SSH.
 *
 * - Host keys are pinned on first use (Account::sshHostKey); a changed key is
 *   refused until an admin resets it on the account form.
 * - Every agent command gets its own timeout; a timed-out or non-JSON answer
 *   becomes ['success' => false, 'error' => ...] instead of a silent partial
 *   result. Old agents (unknown command, missing version) are reported with a
 *   "deploy again" hint.
 * - Rules are uploaded over SFTP and fed to `import-rules` on stdin (no size
 *   limit, no shell quoting of the JSON), which old agents understand too.
 */
class SshService
{
    const CONNECT_TIMEOUT = 15;
    const DEFAULT_TIMEOUT = 60;

    /** Per-command read timeouts (seconds). Initial scans of big mailboxes are slow. */
    const TIMEOUTS = [
        'test' => 60,
        'version' => 30,
        'health' => 60,
        'import-rules' => 300,
        'scan' => 3600,
        'apply-blacklist' => 1800,
        'quarantine-list' => 180,
        'quarantine-release' => 60,
        'quarantine-delete' => 60,
    ];

    /** Directory under which every account's SSH private key must live. */
    private string $keysDir;

    public function __construct(
        #[Autowire('%antispam.ssh_keys_dir%')] string $keysDir,
        private ?ScoringService $scoring = null,
        private ?EntityManagerInterface $em = null,
        private ?MailboxSettingsResolver $mailboxSettings = null,
    ) {
        $this->keysDir = rtrim($keysDir, '/');
    }

    /**
     * Quotes a remote path for the shell. A leading "~/" is turned into
     * "$HOME"/ so it still expands (it would not inside single quotes, nor
     * after "--maildir=").
     */
    public static function shellPath($path)
    {
        $path = (string)$path;
        if ($path === '~') {
            return '"$HOME"';
        }
        if (strncmp($path, '~/', 2) === 0) {
            return '"$HOME"/' . escapeshellarg(substr($path, 2));
        }
        return escapeshellarg($path);
    }

    /** Agent version shipped with this panel (AGENT_VERSION in the agent script). */
    public static function bundledAgentVersion()
    {
        $src = (string)@file_get_contents(self::agentSource());
        return preg_match("/^const AGENT_VERSION = '([^']+)';/m", $src, $m) ? $m[1] : null;
    }

    /** OpenSSH-style SHA256 fingerprint of a "type base64" public host key. */
    public static function fingerprint($publicKey)
    {
        $parts = explode(' ', trim((string)$publicKey));
        $blob = base64_decode($parts[1] ?? $parts[0], true);
        if ($blob === false || $blob === '') {
            throw new \RuntimeException('Nieprawidłowy klucz hosta SSH');
        }
        return 'SHA256:' . rtrim(base64_encode(hash('sha256', $blob, true)), '=');
    }

    private static function agentSource()
    {
        return __DIR__ . '/../Resources/agent/antispam-agent.php';
    }

    private static function agentDir(Account $account)
    {
        $dir = rtrim((string)$account->getAgentPath(), '/');
        return $dir === '' ? '~/antispam-agent' : $dir;
    }

    /** Remote agent invocation: php <agent> <command> <args> [--account=ID]. */
    public function buildAgentCommand(Account $account, $command, $args = '')
    {
        $cmd = 'php ' . self::shellPath(self::agentDir($account) . '/antispam-agent.php') . ' ' . $command;
        if ($args !== '') {
            $cmd .= ' ' . $args;
        }
        // Per-account rules database (agent >= 3.0; older agents ignore it).
        if ($account->getId()) {
            $cmd .= ' --account=' . (int)$account->getId();
        }
        return $cmd;
    }

    private function maildirArg(Account $account)
    {
        return '--maildir=' . self::shellPath($account->getMaildirPath());
    }

    public function testConnection(Account $account)
    {
        $result = ['success' => false, 'messages' => []];

        try {
            $ssh = $this->connect($account);
            $result['messages'][] = 'SSH connection OK';
            $result['messages'][] = 'Host key: ' . $account->getSshHostKey();
            $ssh->setTimeout(self::DEFAULT_TIMEOUT);

            $output = $ssh->exec('php -v 2>&1 | head -1');
            $result['messages'][] = 'PHP: ' . trim((string)$output);

            $output = (string)$ssh->exec('php -m 2>/dev/null');
            foreach (['sqlite3' => 'SQLite3', 'mbstring' => 'mbstring', 'curl' => 'curl (optional)'] as $ext => $label) {
                $result['messages'][] = $label . ': ' . (preg_match('/^' . $ext . '$/mi', $output) ? 'available' : 'NOT available');
            }

            $maildirPath = $account->getMaildirPath();
            $output = $ssh->exec('test -d ' . self::shellPath($maildirPath) . " && echo 'exists' || echo 'not found'");
            $result['messages'][] = 'Maildir (' . $maildirPath . '): ' . trim((string)$output);

            $result['success'] = true;
            $ssh->disconnect();
        } catch (\Exception $e) {
            $result['messages'][] = 'Error: ' . $e->getMessage();
        }

        return $result;
    }

    /** Logged-in SSH session; the host key is verified (TOFU) before login. */
    public function connect(Account $account)
    {
        $ssh = $this->createSsh($account);
        $this->authenticate($ssh, $account);
        return $ssh;
    }

    /** Logged-in SFTP session (same host key / key file checks). */
    public function connectSftp(Account $account)
    {
        $sftp = $this->createSftp($account);
        $this->authenticate($sftp, $account);
        return $sftp;
    }

    protected function createSsh(Account $account)
    {
        return new SSH2((string)$account->getSshHost(), (int)($account->getSshPort() ?: 22), self::CONNECT_TIMEOUT);
    }

    protected function createSftp(Account $account)
    {
        return new SFTP((string)$account->getSshHost(), (int)($account->getSshPort() ?: 22), self::CONNECT_TIMEOUT);
    }

    /**
     * Trust on first use: the first successful login stores the server's
     * SHA256 host key fingerprint on the account; later connections must
     * present the same key (checked before any credentials are sent).
     */
    private function authenticate(SSH2 $ssh, Account $account)
    {
        $hostKey = $ssh->getServerPublicHostKey();
        if ($hostKey === false) {
            throw new \RuntimeException('Serwer SSH ' . $account->getSshHost() . ' nie potwierdził swojego klucza hosta (nieprawidłowy podpis)');
        }
        $fingerprint = self::fingerprint($hostKey);
        $known = (string)$account->getSshHostKey();
        if ($known !== '' && !hash_equals($known, $fingerprint)) {
            throw new HostKeyMismatchException(sprintf(
                'Klucz hosta SSH serwera %s zmienił się (zapisany: %s, obecny: %s). Możliwy atak man-in-the-middle '
                . '- połączenie przerwane. Jeśli zmiana jest zamierzona (reinstalacja serwera, nowy klucz), sprawdź '
                . 'odcisk u administratora serwera i zresetuj zapisany klucz w edycji konta.',
                $account->getSshHost(), $known, $fingerprint
            ));
        }

        $key = PublicKeyLoader::load($this->loadKeyMaterial($account));
        if (!$ssh->login((string)$account->getSshUser(), $key)) {
            throw new \RuntimeException('SSH key authentication failed');
        }

        if ($known === '') {
            $this->trustHostKey($account, $fingerprint);
        }
    }

    private function trustHostKey(Account $account, $fingerprint)
    {
        $account->setSshHostKey($fingerprint);
        // Direct UPDATE: callers do not always flush, and a flush here would
        // write unrelated pending changes.
        if ($this->em && $account->getId()) {
            $this->em->getConnection()->update('antispam_account', ['ssh_host_key' => $fingerprint], ['id' => $account->getId()]);
        }
    }

    /** Runs a raw command and returns its stdout (stderr is discarded). */
    public function exec(Account $account, $command, $timeout = self::DEFAULT_TIMEOUT)
    {
        return $this->execute($account, $command, $timeout)['output'];
    }

    /**
     * @return array{output:string, stderr:string, exit:int|false, timeout:bool}
     */
    private function execute(Account $account, $command, $timeout)
    {
        $ssh = $this->connect($account);
        try {
            $ssh->setTimeout($timeout);
            $ssh->setKeepAlive(30);
            $ssh->enableQuietMode(); // keep stderr out of the JSON on stdout
            $output = $ssh->exec($command);
            return [
                'output' => is_string($output) ? $output : '',
                'stderr' => (string)$ssh->getStdError(),
                'exit' => $ssh->getExitStatus(),
                'timeout' => (bool)$ssh->isTimeout(),
            ];
        } finally {
            $ssh->disconnect();
        }
    }

    /** Runs an agent command and returns its decoded JSON answer. */
    private function runAgent(Account $account, $command, $args = '', $suffix = '')
    {
        $timeout = self::TIMEOUTS[$command] ?? self::DEFAULT_TIMEOUT;
        $raw = $this->execute($account, $this->buildAgentCommand($account, $command, $args) . $suffix, $timeout);
        return $this->interpret($command, $raw, $timeout);
    }

    /**
     * Turns raw command output into the agent's answer, or a failure with a
     * message an admin can act on.
     */
    public function interpret($command, array $raw, $timeout)
    {
        if (!empty($raw['timeout'])) {
            return [
                'success' => false,
                'timeout' => true,
                'error' => sprintf('Agent nie odpowiedział w ciągu %d s (polecenie %s); operacja mogła nie dokończyć się na serwerze.', $timeout, $command),
            ];
        }

        $data = self::decodeAgentJson($raw['output'] ?? '');
        if (is_array($data)) {
            $bundled = self::bundledAgentVersion();
            if (!isset($data['agent_version']) || ($bundled && version_compare((string)$data['agent_version'], $bundled, '<'))) {
                $data['agent_outdated'] = true;
                $data['agent_warning'] = 'Agent na serwerze jest w starszej wersji (' . ($data['agent_version'] ?? '< 3.0')
                    . ') niż w panelu (' . $bundled . ') - wdróż go ponownie (Konta → Wdróż).';
            }
            return $data;
        }

        $text = trim(($raw['output'] ?? '') . "\n" . ($raw['stderr'] ?? ''));
        $exit = $raw['exit'] ?? false;
        if (strpos($text, 'Antispam Maildir Agent') !== false && strpos($text, 'Usage:') !== false) {
            $error = sprintf('Agent na serwerze nie obsługuje polecenia "%s" (starsza wersja) - wdróż go ponownie (Konta → Wdróż).', $command);
        } elseif (stripos($text, 'Could not open input file') !== false) {
            $error = 'Nie znaleziono agenta na serwerze - wdróż go (Konta → Wdróż).';
        } elseif ($exit === 127 || stripos($text, 'php: command not found') !== false || stripos($text, 'php: not found') !== false) {
            $error = 'Brak PHP CLI (polecenie "php") na serwerze.';
        } else {
            $error = 'Nieprawidłowa odpowiedź agenta' . ($exit !== false ? ' (kod wyjścia ' . $exit . ')' : '') . ': '
                . ($text === '' ? '(brak danych)' : mb_substr($text, 0, 500));
        }
        return ['success' => false, 'error' => $error, 'exit_status' => $exit];
    }

    /**
     * Decodes the agent's JSON document. Tolerates noise before it (PHP
     * warnings printed by old agents with display_errors on).
     */
    public static function decodeAgentJson($output)
    {
        $output = trim((string)$output);
        if ($output === '') {
            return null;
        }
        $data = json_decode($output, true);
        if (is_array($data)) {
            return $data;
        }
        if (preg_match('/^\{/m', $output, $m, PREG_OFFSET_CAPTURE) && ($end = strrpos($output, '}')) !== false) {
            $data = json_decode(substr($output, $m[0][1], $end - $m[0][1] + 1), true);
            if (is_array($data)) {
                return $data;
            }
        }
        return null;
    }

    /**
     * Uploads a local file. "~" / "~/x" and relative paths are resolved
     * against the SFTP start directory (the home directory) - SFTP itself
     * does no tilde expansion. The file is created owner-only first and gets
     * $mode once complete.
     *
     * @return string absolute remote path
     */
    public function upload(Account $account, $localPath, $remotePath, $mode = 0600)
    {
        $data = @file_get_contents($localPath);
        if ($data === false) {
            throw new \RuntimeException('Nie można odczytać pliku ' . $localPath);
        }
        $sftp = $this->connectSftp($account);
        try {
            $remote = self::resolveRemotePath((string)$remotePath, $sftp->pwd());
            $dir = dirname($remote);
            if (!$sftp->is_dir($dir)) {
                $sftp->mkdir($dir, 0700, true);
                if (!$sftp->is_dir($dir)) {
                    throw new \RuntimeException('Nie można utworzyć katalogu ' . $dir . ' na serwerze: ' . $sftp->getLastSFTPError());
                }
            }
            if ($sftp->put($remote, '') !== true || $sftp->chmod(0600, $remote) === false) {
                throw new \RuntimeException('Nie można zapisać pliku ' . $remote . ' na serwerze: ' . $sftp->getLastSFTPError());
            }
            if ($sftp->put($remote, $data) !== true) {
                throw new \RuntimeException('Nie można zapisać pliku ' . $remote . ' na serwerze: ' . $sftp->getLastSFTPError());
            }
            $stat = $sftp->stat($remote);
            if (!is_array($stat) || (int)($stat['size'] ?? -1) !== strlen($data)) {
                throw new \RuntimeException('Plik ' . $remote . ' na serwerze ma nieprawidłowy rozmiar po wysłaniu');
            }
            if ($mode !== 0600) {
                $sftp->chmod($mode, $remote);
            }
            return $remote;
        } finally {
            $sftp->disconnect();
        }
    }

    /** @param string|false $home SFTP start directory */
    public static function resolveRemotePath($path, $home)
    {
        $path = trim($path);
        if ($path === '' || $path[0] !== '/') {
            if ($home === false || $home === '' || $home === null) {
                throw new \RuntimeException('Nie można ustalić katalogu domowego przez SFTP - podaj bezwzględną ścieżkę agenta');
            }
            $home = rtrim($home, '/');
            if ($path === '~' || $path === '') {
                return $home === '' ? '/' : $home;
            }
            $path = $home . '/' . (strncmp($path, '~/', 2) === 0 ? substr($path, 2) : $path);
        }
        if (in_array('..', explode('/', $path), true)) {
            throw new \RuntimeException('Ścieżka nie może zawierać ".."');
        }
        return $path;
    }

    /**
     * Uploads the bundled agent and runs its self-test against the account's
     * Maildir. 'success' is true only when the upload worked and the test
     * passed; the caller must not mark the agent deployed otherwise.
     */
    public function deployAgent(Account $account)
    {
        $remote = $this->upload($account, self::agentSource(), self::agentDir($account) . '/antispam-agent.php', 0600);

        $test = $this->runAgent($account, 'test', $this->maildirArg($account));
        $test['remote_path'] = $remote;
        if (($test['success'] ?? null) !== true) {
            $problems = array_filter(array_merge((array)($test['errors'] ?? []), [(string)($test['error'] ?? '')]));
            $test['success'] = false;
            $test['error'] = 'Agent wysłany do ' . $remote . ', ale test na serwerze nie przeszedł'
                . ($problems ? ': ' . implode('; ', $problems) : '');
        }
        return $test;
    }

    /**
     * Pushes rules.json: uploaded over SFTP (owner-only file next to the
     * agent), fed to `import-rules` on stdin and removed again.
     */
    public function syncRules(Account $account, $rulesJson)
    {
        $tmp = tempnam(sys_get_temp_dir(), 'agent-rules');
        if ($tmp === false || file_put_contents($tmp, (string)$rulesJson) === false) {
            throw new \RuntimeException('Nie można przygotować pliku z regułami');
        }
        try {
            $remote = $this->upload($account, $tmp, self::agentDir($account) . '/.rules-import-' . bin2hex(random_bytes(6)) . '.json', 0600);
        } finally {
            @unlink($tmp);
        }

        $file = escapeshellarg($remote);
        return $this->runAgent($account, 'import-rules', '', ' < ' . $file . '; rc=$?; rm -f ' . $file . '; exit $rc');
    }

    /**
     * Scan options default to the panel's current scoring configuration -
     * the account's effective values (Ustawienia skrzynki override -> global),
     * so the agent uses the same thresholds and switches even before the next
     * rules sync (and with agents older than 3.0, which ignore the synced
     * values).
     */
    public function runScan(Account $account, array $options = [])
    {
        $options += $this->mailboxSettings
            ? $this->mailboxSettings->within($account, fn () => $this->scanDefaults())
            : $this->scanDefaults();
        $args = $this->maildirArg($account);
        if (isset($options['spam_threshold'])) {
            $args .= ' --spam-threshold=' . (int)$options['spam_threshold'];
        }
        if (isset($options['quarantine_threshold'])) {
            $args .= ' --quarantine-threshold=' . (int)$options['quarantine_threshold'];
        }
        foreach (['no_dnsbl', 'no_headers', 'no_impersonation', 'no_urls', 'no_cert', 'no_attachment_policy', 'no_clamav', 'no_virustotal'] as $flag) {
            if (!empty($options[$flag])) {
                $args .= ' --' . str_replace('_', '-', $flag);
            }
        }

        return $this->runAgent($account, 'scan', $args);
    }

    private function scanDefaults()
    {
        if (!$this->scoring) {
            return [];
        }
        $s = $this->scoring;
        $out = [
            'spam_threshold' => $s->getSpamThreshold(),
            'quarantine_threshold' => $s->getQuarantineThreshold(),
            'no_dnsbl' => !$s->isDnsblEnabled(),
            'no_headers' => !$s->isHeaderCheckEnabled(),
        ];
        if (!$s->isScoringEnabled()) {
            foreach (['no_dnsbl', 'no_headers', 'no_impersonation', 'no_urls', 'no_cert', 'no_attachment_policy', 'no_clamav', 'no_virustotal'] as $flag) {
                $out[$flag] = true;
            }
        }
        return $out;
    }

    /**
     * Retroactive pass: move recent INBOX mail matching the (already synced)
     * blacklists to .SPAM. Needs an agent deployed with this command.
     */
    public function applyBlacklist(Account $account, $spamThreshold, $days = 30)
    {
        $args = $this->maildirArg($account) . ' --spam-threshold=' . (int)$spamThreshold . ' --days=' . (int)$days;
        return $this->runAgent($account, 'apply-blacklist', $args);
    }

    /**
     * @param int|null $since only messages delivered after this unix timestamp
     */
    public function quarantineList(Account $account, $since = null, $limit = 200)
    {
        $args = $this->maildirArg($account) . ' --limit=' . (int)$limit;
        if ($since) {
            $args .= ' --since=' . (int)$since;
        }
        return $this->runAgent($account, 'quarantine-list', $args);
    }

    /**
     * @param string $action release | delete
     */
    public function quarantineAction(Account $account, $action, $id, $whitelist = false)
    {
        if (!in_array($action, ['release', 'delete'], true)) {
            throw new \InvalidArgumentException('Unknown quarantine action: ' . $action);
        }
        $args = $this->maildirArg($account) . ' --id=' . escapeshellarg((string)$id);
        if ($whitelist && $action === 'release') {
            $args .= ' --whitelist';
        }
        return $this->runAgent($account, 'quarantine-' . $action, $args);
    }

    public function runHealth(Account $account)
    {
        return $this->runAgent($account, 'health', $this->maildirArg($account));
    }

    /**
     * Reads the account's private key. The path must resolve inside the keys
     * directory, so the ssh_key_path field cannot be used to read other local
     * files.
     */
    private function loadKeyMaterial(Account $account)
    {
        $keyPath = (string)$account->getSshKeyPath();
        if ($keyPath === '') {
            throw new \RuntimeException('SSH key path is not set');
        }
        if (strpos($keyPath, '/') !== 0) {
            $keyPath = $this->keysDir . '/' . $keyPath;
        }
        $real = realpath($keyPath);
        $base = realpath($this->keysDir);
        if ($real === false || !is_file($real)) {
            throw new \RuntimeException('SSH key file not found: ' . $account->getSshKeyPath());
        }
        if ($base === false || strncmp($real, $base . '/', strlen($base) + 1) !== 0) {
            throw new \RuntimeException('SSH key must be inside the keys directory: ' . $this->keysDir);
        }
        return file_get_contents($real);
    }
}
