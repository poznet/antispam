<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use phpseclib3\Net\SSH2;
use phpseclib3\Net\SFTP;
use phpseclib3\Crypt\PublicKeyLoader;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

class SshService
{
    /** Directory under which every account's SSH private key must live. */
    private string $keysDir;

    public function __construct(#[Autowire('%antispam.ssh_keys_dir%')] string $keysDir)
    {
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

    private function agentCommand(Account $account)
    {
        return 'php ' . self::shellPath(rtrim((string)$account->getAgentPath(), '/') . '/antispam-agent.php');
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

            $output = $ssh->exec('php -v 2>&1 | head -1');
            $result['messages'][] = 'PHP: ' . trim($output);

            $output = $ssh->exec('php -m 2>/dev/null | grep -i sqlite3');
            $result['messages'][] = trim($output) ? 'SQLite3: available' : 'SQLite3: NOT available';

            $maildirPath = $account->getMaildirPath();
            $output = $ssh->exec('test -d ' . self::shellPath($maildirPath) . " && echo 'exists' || echo 'not found'");
            $result['messages'][] = 'Maildir (' . $maildirPath . '): ' . trim($output);

            $result['success'] = true;
            $ssh->disconnect();
        } catch (\Exception $e) {
            $result['messages'][] = 'Error: ' . $e->getMessage();
        }

        return $result;
    }

    public function connect(Account $account)
    {
        $ssh = new SSH2($account->getSshHost(), $account->getSshPort());
        $key = PublicKeyLoader::load($this->loadKeyMaterial($account));
        if (!$ssh->login($account->getSshUser(), $key)) {
            throw new \RuntimeException('SSH key authentication failed');
        }

        return $ssh;
    }

    public function exec(Account $account, $command)
    {
        $ssh = $this->connect($account);
        $output = $ssh->exec($command);
        $ssh->disconnect();
        return $output;
    }

    public function upload(Account $account, $localPath, $remotePath)
    {
        $sftp = new SFTP($account->getSshHost(), $account->getSshPort());

        $key = PublicKeyLoader::load($this->loadKeyMaterial($account));
        if (!$sftp->login($account->getSshUser(), $key)) {
            throw new \RuntimeException('SFTP authentication failed');
        }

        $remoteDir = dirname($remotePath);
        $sftp->mkdir($remoteDir, 0755, true);

        $result = $sftp->put($remotePath, $localPath, SFTP::SOURCE_LOCAL_FILE);
        $sftp->disconnect();

        return $result;
    }

    public function deployAgent(Account $account)
    {
        $agentSource = __DIR__ . '/../Resources/agent/antispam-agent.php';
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';

        $this->upload($account, $agentSource, $remotePath);

        $output = $this->exec($account, $this->agentCommand($account) . ' test 2>&1');
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function syncRules(Account $account, $rulesJson)
    {
        $cmd = 'echo ' . escapeshellarg($rulesJson) . ' | ' . $this->agentCommand($account) . ' import-rules 2>&1';
        $output = $this->exec($account, $cmd);
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function runScan(Account $account, array $options = [])
    {
        $args = $this->maildirArg($account);
        if (isset($options['spam_threshold'])) {
            $args .= ' --spam-threshold=' . (int)$options['spam_threshold'];
        }
        if (isset($options['quarantine_threshold'])) {
            $args .= ' --quarantine-threshold=' . (int)$options['quarantine_threshold'];
        }
        if (!empty($options['no_dnsbl'])) { $args .= ' --no-dnsbl'; }
        if (!empty($options['no_headers'])) { $args .= ' --no-headers'; }

        $output = $this->exec($account, $this->agentCommand($account) . ' scan ' . $args . ' 2>&1');
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    /**
     * Retroactive pass: move recent INBOX mail matching the (already synced)
     * blacklists to .SPAM. Needs an agent deployed with this command.
     */
    public function applyBlacklist(Account $account, $spamThreshold, $days = 30)
    {
        $args = $this->maildirArg($account) . ' --spam-threshold=' . (int)$spamThreshold . ' --days=' . (int)$days;
        $output = $this->exec($account, $this->agentCommand($account) . ' apply-blacklist ' . $args . ' 2>&1');
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
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
        $output = $this->exec($account, $this->agentCommand($account) . ' quarantine-list ' . $args . ' 2>&1');
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
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
        $output = $this->exec($account, $this->agentCommand($account) . ' quarantine-' . $action . ' ' . $args . ' 2>&1');
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function runHealth(Account $account)
    {
        $output = $this->exec($account, $this->agentCommand($account) . ' health ' . $this->maildirArg($account) . ' 2>&1');
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
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
