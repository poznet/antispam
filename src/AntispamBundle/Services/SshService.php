<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use phpseclib3\Net\SSH2;
use phpseclib3\Net\SFTP;
use phpseclib3\Crypt\PublicKeyLoader;

class SshService
{
    /** Absolute directory under which SSH private keys must live. */
    private $keysDir;

    public function __construct($keysDir = null)
    {
        $this->keysDir = $keysDir ? rtrim($keysDir, '/') : null;
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
            $output = $ssh->exec('test -d ' . escapeshellarg($maildirPath) . " && echo 'exists' || echo 'not found'");
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

        $output = $this->exec($account, 'php ' . escapeshellarg($remotePath) . ' test 2>&1');
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function syncRules(Account $account, $rulesJson)
    {
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';
        $cmd = 'echo ' . escapeshellarg($rulesJson)
            . ' | php ' . escapeshellarg($remotePath) . ' import-rules 2>&1';
        $output = $this->exec($account, $cmd);
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function runScan(Account $account, array $options = [])
    {
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';
        $maildirPath = $account->getMaildirPath();

        $args = '--maildir=' . escapeshellarg($maildirPath);
        if (isset($options['spam_threshold'])) {
            $args .= ' --spam-threshold=' . (int)$options['spam_threshold'];
        }
        if (isset($options['quarantine_threshold'])) {
            $args .= ' --quarantine-threshold=' . (int)$options['quarantine_threshold'];
        }
        if (!empty($options['no_dnsbl'])) { $args .= ' --no-dnsbl'; }
        if (!empty($options['no_headers'])) { $args .= ' --no-headers'; }

        $output = $this->exec($account, 'php ' . escapeshellarg($remotePath) . ' scan ' . $args . ' 2>&1');
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function runHealth(Account $account)
    {
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';
        $maildirPath = $account->getMaildirPath();
        $cmd = 'php ' . escapeshellarg($remotePath) . ' health --maildir='
            . escapeshellarg($maildirPath) . ' 2>&1';
        $output = $this->exec($account, $cmd);
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    /**
     * Load the SSH private key material from disk, enforcing that the path
     * lives under the configured keys directory. This blocks arbitrary local
     * file reads (LFI) through the user-controlled ssh_key_path field.
     */
    private function loadKeyMaterial(Account $account)
    {
        $keyPath = (string)$account->getSshKeyPath();
        if ($keyPath === '') {
            throw new \RuntimeException('SSH key path is not set');
        }
        if (!$this->keysDir) {
            throw new \RuntimeException('SSH keys directory is not configured (antispam.ssh_keys_dir)');
        }
        $real = realpath($keyPath);
        $baseReal = realpath($this->keysDir);
        if ($real === false || $baseReal === false) {
            throw new \RuntimeException('SSH key file not found');
        }
        if (strncmp($real, $baseReal . '/', strlen($baseReal) + 1) !== 0) {
            throw new \RuntimeException('SSH key path is outside the allowed keys directory');
        }
        return file_get_contents($real);
    }
}
