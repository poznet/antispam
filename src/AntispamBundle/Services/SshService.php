<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use phpseclib3\Net\SSH2;
use phpseclib3\Net\SFTP;
use phpseclib3\Crypt\PublicKeyLoader;

class SshService
{
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
            $output = $ssh->exec("test -d {$maildirPath} && echo 'exists' || echo 'not found'");
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

        $keyPath = $account->getSshKeyPath();
        if ($keyPath && file_exists($keyPath)) {
            $key = PublicKeyLoader::load(file_get_contents($keyPath));
            if (!$ssh->login($account->getSshUser(), $key)) {
                throw new \RuntimeException('SSH key authentication failed');
            }
        } else {
            throw new \RuntimeException('SSH key file not found: ' . $keyPath);
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

        $keyPath = $account->getSshKeyPath();
        $key = PublicKeyLoader::load(file_get_contents($keyPath));
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

        $output = $this->exec($account, "php {$remotePath} test 2>&1");
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function syncRules(Account $account, $rulesJson)
    {
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';
        $escapedJson = escapeshellarg($rulesJson);
        $output = $this->exec($account, "echo {$escapedJson} | php {$remotePath} import-rules 2>&1");
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function runScan(Account $account)
    {
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';
        $maildirPath = $account->getMaildirPath();
        $output = $this->exec($account, "php {$remotePath} scan --maildir={$maildirPath} 2>&1");
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }
}
