<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use phpseclib3\Net\SSH2;
use phpseclib3\Net\SFTP;
use phpseclib3\Crypt\PublicKeyLoader;

class SshService
{
    private $keyEncryption;

    public function __construct(KeyEncryptionService $keyEncryption = null)
    {
        $this->keyEncryption = $keyEncryption;
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
        $key = $this->loadKey($account);

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
        $key = $this->loadKey($account);

        if (!$sftp->login($account->getSshUser(), $key)) {
            throw new \RuntimeException('SFTP authentication failed');
        }

        $remoteDir = dirname($remotePath);
        $sftp->mkdir($remoteDir, 0755, true);

        $result = $sftp->put($remotePath, $localPath, SFTP::SOURCE_LOCAL_FILE);
        $sftp->disconnect();

        return $result;
    }

    private function loadKey(Account $account)
    {
        // Try inline key first (stored in database)
        $keyContent = $account->getSshKeyPrivate();
        if ($keyContent) {
            // Decrypt if encryption service is available
            if ($this->keyEncryption) {
                $decrypted = $this->keyEncryption->decrypt($keyContent);
                if ($decrypted) {
                    $keyContent = $decrypted;
                }
            }

            $passphrase = $account->getSshKeyPassphrase();
            if ($passphrase && $this->keyEncryption) {
                $passphrase = $this->keyEncryption->decrypt($passphrase) ?: $passphrase;
            }

            return PublicKeyLoader::load($keyContent, $passphrase ?: false);
        }

        // Fallback to key file path
        $keyPath = $account->getSshKeyPath();
        if ($keyPath && file_exists($keyPath)) {
            return PublicKeyLoader::load(file_get_contents($keyPath));
        }

        throw new \RuntimeException('No SSH key configured: provide either a key file path or paste the private key');
    }
}
