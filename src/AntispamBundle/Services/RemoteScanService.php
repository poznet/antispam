<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\ScanLog;
use Doctrine\ORM\EntityManagerInterface;

class RemoteScanService
{
    private $ssh;
    private $em;

    public function __construct(SshService $ssh, EntityManagerInterface $em)
    {
        $this->ssh = $ssh;
        $this->em = $em;
    }

    public function scan(Account $account)
    {
        $startTime = microtime(true);

        try {
            $remotePath = $account->getAgentPath() . '/antispam-agent.php';
            $maildirPath = $account->getMaildirPath();
            $output = $this->ssh->exec($account, "php {$remotePath} scan --maildir={$maildirPath} 2>&1");
            $result = json_decode($output, true) ?: ['success' => false, 'error' => $output];

            $durationMs = (int)((microtime(true) - $startTime) * 1000);

            $account->setLastScanAt(new \DateTime());
            $account->setLastScanResult(json_encode($result));

            $scanLog = ScanLog::fromScanResult($account, $result, $durationMs);
            $this->em->persist($scanLog);
            $this->em->flush();

            return $result;
        } catch (\Exception $e) {
            $durationMs = (int)((microtime(true) - $startTime) * 1000);

            $scanLog = ScanLog::fromError($account, $e->getMessage(), $durationMs);
            $this->em->persist($scanLog);
            $this->em->flush();

            throw $e;
        }
    }

    public function scanImap(Account $account)
    {
        $startTime = microtime(true);

        try {
            $server = new \Ddeboer\Imap\Server(
                $account->getImapHost(),
                $account->getImapPort(),
                $account->getImapFlags()
            );
            $connection = $server->authenticate($account->getImapLogin(), $account->getImapPassword());
            $inbox = $connection->getMailbox('INBOX');
            $messages = $inbox->getMessages();

            $stats = ['total' => 0, 'checked' => 0, 'whitelisted' => 0, 'blacklisted' => 0, 'moved_to_spam' => 0];

            foreach ($messages as $msg) {
                $stats['total']++;
                $stats['checked']++;

                try {
                    $senderHeaders = $msg->getHeaders()->get('sender');
                    if (empty($senderHeaders)) continue;

                    $host = $senderHeaders[0]->host ?? '';
                    $senderEmail = ($senderHeaders[0]->mailbox ?? '') . '@' . $host;

                    $wl = $this->em->getRepository('AntispamBundle:Whitelist')->findOneBy(['host' => $host, 'email' => $account->getEmail()]);
                    if ($wl) { $stats['whitelisted']++; continue; }

                    $ewl = $this->em->getRepository('AntispamBundle:EmailWhitelist')->findOneBy(['whitelistemail' => $senderEmail, 'email' => $account->getEmail()]);
                    if ($ewl) { $stats['whitelisted']++; continue; }

                    $bl = $this->em->getRepository('AntispamBundle:Blacklist')->findOneBy(['host' => $host, 'email' => $account->getEmail()]);
                    $ebl = $this->em->getRepository('AntispamBundle:EmailBlacklist')->findOneBy(['blacklistemail' => $senderEmail, 'email' => $account->getEmail()]);

                    if ($bl || $ebl) {
                        $stats['blacklisted']++;
                        if (!$account->getDeleteSpam()) {
                            if (!$connection->hasMailbox('SPAM')) {
                                $connection->createMailbox('SPAM');
                            }
                            $spambox = $connection->getMailbox('SPAM');
                            $msg->move($spambox);
                            $stats['moved_to_spam']++;
                        }
                    }
                } catch (\Exception $e) {
                    // Skip messages with encoding issues
                }
            }

            $connection->close();

            $durationMs = (int)((microtime(true) - $startTime) * 1000);

            $account->setLastScanAt(new \DateTime());
            $account->setLastScanResult(json_encode($stats));

            $scanLog = ScanLog::fromScanResult($account, $stats, $durationMs);
            $this->em->persist($scanLog);
            $this->em->flush();

            return $stats;
        } catch (\Exception $e) {
            $durationMs = (int)((microtime(true) - $startTime) * 1000);

            $scanLog = ScanLog::fromError($account, $e->getMessage(), $durationMs);
            $this->em->persist($scanLog);
            $this->em->flush();

            throw $e;
        }
    }
}
