<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\RescanScheduler;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Queues the weekly full rescans that are due (accounts with "Cotygodniowy
 * ponowny skan" on, see RescanScheduler). Only queues background jobs
 * (`account.rescan`); the job worker runs them. Meant to run hourly:
 *
 *     php bin/console antispam:cron:run antispam:rescan:due
 *     php bin/console antispam:rescan:due --dry-run
 *     php bin/console antispam:rescan:due --account=12     # queue one rescan now
 */
#[AsCommand(name: 'antispam:rescan:due', description: 'Queue the weekly full mailbox rescans that are due')]
class RescanDueCommand extends Command
{
    public function __construct(
        private EntityManagerInterface $em,
        private RescanScheduler $scheduler,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('dry-run', null, InputOption::VALUE_NONE, 'Only list the due accounts')
             ->addOption('account', null, InputOption::VALUE_REQUIRED, 'Queue a rescan of this account id now, whatever its schedule');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if (($id = $input->getOption('account')) !== null) {
            $account = ctype_digit((string)$id) ? $this->em->find(Account::class, (int)$id) : null;
            if (!$account) {
                $output->writeln('<error>No account with id ' . $id . '</error>');
                return Command::INVALID;
            }
            $accounts = [$account];
        } else {
            $accounts = $this->scheduler->dueAccounts();
        }

        if (!$accounts) {
            $output->writeln('No rescan due.');
            return Command::SUCCESS;
        }
        foreach ($accounts as $account) {
            $name = sprintf('%s (%s)', $account->getEmail(), $account->getConnectionType());
            if ($input->getOption('dry-run')) {
                $output->writeln($name . ': due');
                continue;
            }
            $queued = $this->scheduler->enqueue($account, $input->getOption('account') !== null ? RescanScheduler::TRIGGER_CLI : RescanScheduler::TRIGGER_SCHEDULE);
            $output->writeln($queued->created
                ? sprintf('%s: rescan queued (job #%d)', $name, $queued->id)
                : sprintf('%s: rescan already %s (job #%d)', $name, $queued->existingStatus, $queued->id));
        }
        return Command::SUCCESS;
    }
}
