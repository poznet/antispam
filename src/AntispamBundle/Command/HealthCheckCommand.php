<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\HealthAlerter;
use AntispamBundle\Services\HealthService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs the health checks and sends alerts (e-mail / webhook) for checks that
 * started failing or recovered. Run by the scheduler every
 * HEALTH_CHECK_INTERVAL minutes (see docs/health.md).
 *
 * Exits 0 even when checks fail, so the cron log does not report the monitor
 * itself as broken; --exit-code returns 1 for degraded and 2 for fail.
 */
#[AsCommand(name: 'antispam:health:check', description: 'Run the health checks and send alerts on state changes')]
class HealthCheckCommand extends Command
{
    public function __construct(private HealthService $health, private HealthAlerter $alerter)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('full', null, InputOption::VALUE_NONE, 'Also log in to every IMAP account, query every SSH agent and diff the schema (slow)')
            ->addOption('no-alert', null, InputOption::VALUE_NONE, 'Only print the checks, do not update the alert state or send anything')
            ->addOption('json', null, InputOption::VALUE_NONE, 'Print the report as JSON')
            ->addOption('exit-code', null, InputOption::VALUE_NONE, 'Exit 1 when degraded, 2 when failing');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $report = $this->health->run((bool)$input->getOption('full'));

        if ($input->getOption('json')) {
            $output->writeln(json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        } else {
            foreach ($report['checks'] as $check) {
                $tag = ['ok' => 'info', 'warn' => 'comment', 'fail' => 'error', 'skip' => 'comment'][$check['status']] ?? 'info';
                $output->writeln(sprintf('<%s>%-4s</%s> %s: %s', $tag, strtoupper($check['status']), $tag, $check['label'], $check['message']));
            }
            $output->writeln('Status: ' . $report['status']);
        }

        if (!$input->getOption('no-alert')) {
            $result = $this->alerter->process($report);
            foreach ($result['problems'] as $p) {
                $output->writeln('Alert: ' . $p['label']);
            }
            foreach ($result['recovered'] as $r) {
                $output->writeln('Recovery: ' . $r['label']);
            }
            if ($result['sent']) {
                $output->writeln('Notification sent via ' . implode(', ', $result['sent']));
            }
            foreach ($result['errors'] as $error) {
                $output->writeln('<error>' . $error . '</error>');
            }
        }

        if ($input->getOption('exit-code')) {
            return ['ok' => 0, 'degraded' => 1, 'fail' => 2][$report['status']] ?? 2;
        }
        return Command::SUCCESS;
    }
}
