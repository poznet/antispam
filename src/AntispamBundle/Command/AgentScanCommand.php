<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\RemoteScanService;
use AntispamBundle\Services\RuleSyncService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class AgentScanCommand extends Command
{
    protected static $defaultName = 'antispam:agent:scan';

    private $em;
    private $scanService;
    private $syncService;

    public function __construct(EntityManagerInterface $em, RemoteScanService $scanService, RuleSyncService $syncService)
    {
        parent::__construct();
        $this->em = $em;
        $this->scanService = $scanService;
        $this->syncService = $syncService;
    }

    protected function configure()
    {
        $this->setDescription('Run spam scan on an account')
             ->addArgument('accountId', InputArgument::REQUIRED, 'Account ID')
             ->addOption('sync-first', null, InputOption::VALUE_NONE, 'Sync rules before scanning');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $account = $this->em->getRepository('AntispamBundle:Account')->find($input->getArgument('accountId'));
        if (!$account) {
            $output->writeln('<error>Account not found</error>');
            return 1;
        }

        $output->writeln('Scanning ' . $account->getEmail() . ' (' . $account->getConnectionType() . ')...');

        try {
            if ($account->isSsh()) {
                if ($input->getOption('sync-first') || $account->getNeedsSync()) {
                    $output->writeln('Syncing rules first...');
                    $this->syncService->sync($account);
                    $output->writeln('<info>Rules synced</info>');
                }

                $result = $this->scanService->scan($account);
            } else {
                $result = $this->scanService->scanImap($account);
            }

            $output->writeln('<info>Scan completed:</info>');
            $output->writeln('  Total: ' . ($result['total'] ?? 0));
            $output->writeln('  Checked: ' . ($result['checked'] ?? 0));
            $output->writeln('  Skipped: ' . ($result['skipped'] ?? 0));
            $output->writeln('  Whitelisted: ' . ($result['whitelisted'] ?? 0));
            $output->writeln('  Blacklisted: ' . ($result['blacklisted'] ?? 0));
            $output->writeln('  Moved to spam: ' . ($result['moved_to_spam'] ?? 0));
        } catch (\Exception $e) {
            $output->writeln('<error>Scan failed: ' . $e->getMessage() . '</error>');
            return 1;
        }

        return 0;
    }
}
