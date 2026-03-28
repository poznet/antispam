<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\RuleSyncService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class AgentSyncCommand extends Command
{
    protected static $defaultName = 'antispam:agent:sync';

    private $em;
    private $syncService;

    public function __construct(EntityManagerInterface $em, RuleSyncService $syncService)
    {
        parent::__construct();
        $this->em = $em;
        $this->syncService = $syncService;
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

        $counts = $this->syncService->getRuleCounts($account->getEmail());
        $output->writeln('Rules: ' . $counts['whitelist'] . ' whitelist, '
            . $counts['email_whitelist'] . ' email whitelist, '
            . $counts['blacklist'] . ' blacklist, '
            . $counts['email_blacklist'] . ' email blacklist');

        try {
            $result = $this->syncService->sync($account);
            $output->writeln('<info>Rules synced successfully</info>');
            $output->writeln(json_encode($result, JSON_PRETTY_PRINT));
        } catch (\Exception $e) {
            $output->writeln('<error>Sync failed: ' . $e->getMessage() . '</error>');
            return 1;
        }

        return 0;
    }
}
