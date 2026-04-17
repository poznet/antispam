<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class AgentSyncCommand extends Command
{
    protected static $defaultName = 'antispam:agent:sync';

    private $em;
    private $ssh;

    public function __construct(EntityManagerInterface $em, SshService $ssh)
    {
        parent::__construct();
        $this->em = $em;
        $this->ssh = $ssh;
    }

    protected function configure()
    {
        $this->setDescription('Sync blacklist / whitelist / DNSBL rules to remote agent')
             ->addArgument('accountId', InputArgument::REQUIRED, 'Account ID');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $account = $this->em->getRepository('AntispamBundle:Account')->find($input->getArgument('accountId'));
        if (!$account || !$account->isSsh()) {
            $output->writeln('<error>Account not found or not SSH type</error>');
            return 1;
        }

        $output->writeln('Syncing rules for ' . $account->getEmail() . '...');

        $rules = $this->exportRules($account->getEmail());
        $output->writeln(sprintf(
            'Rules: %d wl, %d email-wl, %d bl, %d email-bl, %d dnsbl',
            count($rules['whitelist']), count($rules['email_whitelist']),
            count($rules['blacklist']), count($rules['email_blacklist']),
            count($rules['dnsbl'])
        ));

        try {
            $result = $this->ssh->syncRules($account, json_encode($rules));
            $output->writeln('<info>Rules synced successfully</info>');
            $output->writeln(json_encode($result, JSON_PRETTY_PRINT));
        } catch (\Exception $e) {
            $output->writeln('<error>Sync failed: ' . $e->getMessage() . '</error>');
            return 1;
        }
        return 0;
    }

    private function exportRules($email)
    {
        $rules = [
            'whitelist' => [], 'email_whitelist' => [],
            'blacklist' => [], 'email_blacklist' => [],
            'dnsbl' => [],
        ];

        foreach ($this->em->getRepository('AntispamBundle:Whitelist')->findBy(['email' => $email]) as $item) {
            $rules['whitelist'][] = [
                'email' => $item->getEmail(),
                'host' => $item->getHost(),
                'pattern_type' => $item->getPatternType(),
            ];
        }
        foreach ($this->em->getRepository('AntispamBundle:EmailWhitelist')->findBy(['email' => $email]) as $item) {
            $rules['email_whitelist'][] = [
                'email' => $item->getEmail(),
                'whitelistemail' => $item->getWhitelistemail(),
                'pattern_type' => $item->getPatternType(),
            ];
        }
        foreach ($this->em->getRepository('AntispamBundle:Blacklist')->findBy(['email' => $email]) as $item) {
            $rules['blacklist'][] = [
                'email' => $item->getEmail(),
                'host' => $item->getHost(),
                'pattern_type' => $item->getPatternType(),
                'score' => $item->getScore(),
            ];
        }
        foreach ($this->em->getRepository('AntispamBundle:EmailBlacklist')->findBy(['email' => $email]) as $item) {
            $rules['email_blacklist'][] = [
                'email' => $item->getEmail(),
                'blacklistemail' => $item->getBlacklistemail(),
                'pattern_type' => $item->getPatternType(),
                'score' => $item->getScore(),
            ];
        }
        foreach ($this->em->getRepository('AntispamBundle:DnsblProvider')->findAll() as $prov) {
            $rules['dnsbl'][] = [
                'name' => $prov->getName(),
                'zone' => $prov->getZone(),
                'score' => $prov->getScore(),
                'enabled' => $prov->isEnabled(),
                'cache_ttl' => $prov->getCacheTtl(),
            ];
        }
        return $rules;
    }
}
