<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use Doctrine\ORM\EntityManagerInterface;

class RuleSyncService
{
    private $em;
    private $ssh;

    public function __construct(EntityManagerInterface $em, SshService $ssh)
    {
        $this->em = $em;
        $this->ssh = $ssh;
    }

    public function sync(Account $account)
    {
        $rules = $this->exportRules($account->getEmail());
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';
        $escapedJson = escapeshellarg(json_encode($rules));
        $output = $this->ssh->exec($account, "echo {$escapedJson} | php {$remotePath} import-rules 2>&1");
        $result = json_decode($output, true) ?: ['success' => false, 'error' => $output];

        $account->setLastSyncAt(new \DateTime());
        $account->setNeedsSync(false);
        $this->em->flush();

        return $result;
    }

    public function exportRules($email)
    {
        $rules = ['whitelist' => [], 'email_whitelist' => [], 'blacklist' => [], 'email_blacklist' => []];

        foreach ($this->em->getRepository('AntispamBundle:Whitelist')->findBy(['email' => $email]) as $item) {
            $rules['whitelist'][] = ['email' => $item->getEmail(), 'host' => $item->getHost()];
        }
        foreach ($this->em->getRepository('AntispamBundle:EmailWhitelist')->findBy(['email' => $email]) as $item) {
            $rules['email_whitelist'][] = ['email' => $item->getEmail(), 'whitelistemail' => $item->getWhitelistemail()];
        }
        foreach ($this->em->getRepository('AntispamBundle:Blacklist')->findBy(['email' => $email]) as $item) {
            $rules['blacklist'][] = ['email' => $item->getEmail(), 'host' => $item->getHost()];
        }
        foreach ($this->em->getRepository('AntispamBundle:EmailBlacklist')->findBy(['email' => $email]) as $item) {
            $rules['email_blacklist'][] = ['email' => $item->getEmail(), 'blacklistemail' => $item->getBlacklistemail()];
        }

        return $rules;
    }

    public function getRuleCounts($email)
    {
        $rules = $this->exportRules($email);
        return [
            'whitelist' => count($rules['whitelist']),
            'email_whitelist' => count($rules['email_whitelist']),
            'blacklist' => count($rules['blacklist']),
            'email_blacklist' => count($rules['email_blacklist']),
        ];
    }
}
