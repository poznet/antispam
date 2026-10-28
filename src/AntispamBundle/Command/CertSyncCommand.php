<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\CertHoleService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Downloads the CERT Polska "Lista Ostrzeżeń" (hole.cert.pl) into the
 * antispam_cert_domain table. A no-op while the filter is disabled.
 *
 *     php bin/console antispam:cert:sync [--force]
 */
#[AsCommand(name: 'antispam:cert:sync', description: 'Download the CERT Polska list of dangerous domains (hole.cert.pl)')]
class CertSyncCommand extends Command
{
    public function __construct(private CertHoleService $cert)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('force', 'f', InputOption::VALUE_NONE, 'Sync even when the filter is disabled in the panel');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if (!$this->cert->isEnabled() && !$input->getOption('force')) {
            $output->writeln('<comment>CERT list is disabled (cert.enabled). Nothing to do.</comment>');
            return Command::SUCCESS;
        }

        $started = microtime(true);
        try {
            $result = $this->cert->sync();
        } catch (\Throwable $e) {
            // e.g. the database is down while writing the status keys.
            $result = ['ok' => false, 'message' => get_class($e) . ': ' . $e->getMessage()];
        }
        if (!$result['ok']) {
            $output->writeln('<error>CERT list sync failed: ' . $result['message'] . '</error>');
            return Command::FAILURE;
        }
        $output->writeln(sprintf('<info>%s (%.1fs).</info>', $result['message'], microtime(true) - $started));
        return Command::SUCCESS;
    }
}
