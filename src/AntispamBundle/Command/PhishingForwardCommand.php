<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\PhishingForwardService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Automatic mode of the phishing forward to CERT Polska / SOC: sends reports
 * older than the configured delay that were not marked as false positive.
 * A no-op while the automatic mode is off (the default). Run by the
 * scheduler (PHISHING_FORWARD_INTERVAL) or cron, e.g. every 10 minutes.
 */
#[AsCommand(name: 'antispam:phishing:forward', description: 'Forward pending phishing reports to CERT Polska / SOC (automatic mode)')]
class PhishingForwardCommand extends Command
{
    public function __construct(private PhishingForwardService $forwarder)
    {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if ($this->forwarder->getSettings()['auto_minutes'] <= 0) {
            $output->writeln('<comment>Automatic forwarding is off (Zgłoszenia phishingu → Ustawienia przekazywania).</comment>');
            return Command::SUCCESS;
        }
        if ($errors = $this->forwarder->configurationErrors()) {
            foreach ($errors as $e) {
                $output->writeln('<error>' . $e . '</error>');
            }
            return Command::FAILURE;
        }

        $failed = 0;
        $results = $this->forwarder->forwardPending();
        foreach ($results as $id => $r) {
            $output->writeln(sprintf('#%d %s%s', $id, $r['status'], $r['error'] ? ': ' . $r['error'] : ''));
            if ($r['status'] === 'failed') {
                $failed++;
            }
        }
        $output->writeln(sprintf('%d report(s) processed, %d failed.', count($results), $failed));

        return $failed ? Command::FAILURE : Command::SUCCESS;
    }
}
