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
        $this->setDescription('Sync blacklist/whitelist rules to remote agent')
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
        $output->writeln('Rules: ' . count($rules['whitelist']) . ' whitelist, '
            . count($rules['email_whitelist']) . ' email whitelist, '
            . count($rules['blacklist']) . ' blacklist, '
            . count($rules['email_blacklist']) . ' email blacklist');

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
}
