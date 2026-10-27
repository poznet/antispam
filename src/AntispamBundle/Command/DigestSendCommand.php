<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\QuarantineDigestService;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Sends the end-user quarantine digest. Meant for cron, e.g. daily:
 *
 *   0 7 * * * php bin/console antispam:digest:send
 */
class DigestSendCommand extends Command
{
    protected static $defaultName = 'antispam:digest:send';

    private $digest;

    public function __construct(QuarantineDigestService $digest)
    {
        parent::__construct();
        $this->digest = $digest;
    }

    protected function configure()
    {
        $this->setDescription('Send the quarantine digest e-mail to every mailbox with newly quarantined messages')
             ->addOption('mailbox', 'm', InputOption::VALUE_REQUIRED, 'Only this mailbox key ("imap" or "ssh-<accountId>")')
             ->addOption('since', null, InputOption::VALUE_REQUIRED, 'Include messages since this date/time (e.g. "-3 days"); default: since the previous digest')
             ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Build digests and report counts without sending')
             ->addOption('force', 'f', InputOption::VALUE_NONE, 'Send even when the digest is disabled in settings');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        if (!$this->digest->isEnabled() && !$input->getOption('force') && !$input->getOption('dry-run')) {
            $output->writeln('<comment>Quarantine digest is disabled (Ustawienia → Raport kwarantanny). Use --force to send anyway.</comment>');
            return 0;
        }
        $errors = $this->digest->configurationErrors();
        if ($errors && !$input->getOption('dry-run')) {
            foreach ($errors as $e) {
                $output->writeln('<error>' . $e . '</error>');
            }
            return 1;
        }

        $since = null;
        if ($input->getOption('since')) {
            try {
                $since = new \DateTimeImmutable($input->getOption('since'));
            } catch (\Exception $e) {
                $output->writeln('<error>Invalid --since value</error>');
                return 1;
            }
        }

        $report = $this->digest->sendAll($input->getOption('mailbox'), $since, (bool)$input->getOption('dry-run'));
        if (!$report) {
            $output->writeln('<comment>No mailboxes with a quarantine (configure IMAP or deploy an SSH agent).</comment>');
            return 0;
        }

        $failed = 0;
        $table = new Table($output);
        $table->setHeaders(['Mailbox', 'Recipient', 'Messages', 'Status']);
        foreach ($report as $row) {
            if ($row['status'] === 'error' || $row['status'] === 'rejected') {
                $failed++;
            }
            $table->addRow([$row['key'], $row['recipient'], $row['count'], $row['status'] . ($row['error'] ? ': ' . $row['error'] : '')]);
        }
        $table->render();

        return $failed > 0 ? 1 : 0;
    }
}
