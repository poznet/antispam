<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\RemoteScanService;
use AntispamBundle\Services\RuleSyncService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class AgentScanAllCommand extends Command
{
    protected static $defaultName = 'antispam:agent:scan-all';

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
        $this->setDescription('Run spam scan on all configured accounts')
             ->addOption('sync-first', null, InputOption::VALUE_NONE, 'Sync rules before scanning')
             ->addOption('quiet-ok', null, InputOption::VALUE_NONE, 'Only output on errors (for cron)');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $accounts = $this->em->getRepository('AntispamBundle:Account')->findAll();

        if (empty($accounts)) {
            if (!$input->getOption('quiet-ok')) {
                $output->writeln('<comment>No accounts configured</comment>');
            }
            return 0;
        }

        if (!$input->getOption('quiet-ok')) {
            $output->writeln('Scanning ' . count($accounts) . ' account(s)...');
        }

        $errors = 0;

        foreach ($accounts as $account) {
            try {
                if ($account->isSsh()) {
                    // Auto-sync if needed
                    if ($input->getOption('sync-first') || $account->getNeedsSync()) {
                        $this->syncService->sync($account);
                    }

                    $result = $this->scanService->scan($account);
                } else {
                    $result = $this->scanService->scanImap($account);
                }

                if (!$input->getOption('quiet-ok')) {
                    $output->writeln($account->getEmail() . ' (' . $account->getConnectionType() . '): '
                        . '<info>OK</info> - '
                        . ($result['total'] ?? 0) . ' total, '
                        . ($result['moved_to_spam'] ?? 0) . ' spam');
                }
            } catch (\Exception $e) {
                $output->writeln($account->getEmail() . ': <error>FAILED: ' . $e->getMessage() . '</error>');
                $errors++;
            }
        }

        return $errors > 0 ? 1 : 0;
    }
}
