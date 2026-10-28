<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\Jobs\JobWorker;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Background job worker (docs/jobs.md). Runs the heavy operations queued by
 * the panel (scans, agent deploy / sync, retroactive rule passes, CERT sync...).
 *
 *   php bin/console antispam:jobs:work --time-limit=3600   # Docker scheduler: polls every 2 s, restarted when it exits
 *   php bin/console antispam:jobs:run --once               # crontab, every minute: runs what is due, then exits
 *
 * The time limit only stops it from *starting* jobs; a running job may take
 * up to --job-timeout more. Run at most one worker per installation unless
 * you need parallel jobs (claiming is safe with several).
 */
#[AsCommand(name: 'antispam:jobs:work', description: 'Run queued background jobs (scans, deploys, syncs started from the panel)', aliases: ['antispam:jobs:run'])]
class JobsWorkCommand extends Command
{
    public function __construct(
        private JobWorker $worker,
        #[Autowire('%env(default::JOBS_JOB_TIMEOUT)%')] private ?string $envJobTimeout = null,
        #[Autowire('%env(default::JOBS_BATCH_SECONDS)%')] private ?string $envBatchSeconds = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('once', null, InputOption::VALUE_NONE, 'Run the jobs that are due now, then exit (for a crontab entry)')
            ->addOption('time-limit', null, InputOption::VALUE_REQUIRED, 'Stop starting new jobs after N seconds (0 = run until stopped; with --once default 50)')
            ->addOption('memory-limit', null, InputOption::VALUE_REQUIRED, 'Exit after a job when memory use exceeds N MB', '256')
            ->addOption('sleep', null, InputOption::VALUE_REQUIRED, 'Seconds between polls of an empty queue', '2')
            ->addOption('job-timeout', null, InputOption::VALUE_REQUIRED, 'Seconds one job may run before it is killed (0 = no limit; env JOBS_JOB_TIMEOUT)')
            ->addOption('batch-seconds', null, InputOption::VALUE_REQUIRED, 'Length of one batch of a big IMAP scan before it re-queues itself (env JOBS_BATCH_SECONDS)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $once = (bool)$input->getOption('once');
        $ints = [];
        foreach ([
            'time-limit' => $once ? 50 : 0,
            'memory-limit' => 256,
            'sleep' => 2,
            'job-timeout' => self::envInt($this->envJobTimeout, JobWorker::DEFAULT_JOB_TIMEOUT),
            'batch-seconds' => self::envInt($this->envBatchSeconds, JobWorker::DEFAULT_BATCH_SECONDS),
        ] as $name => $default) {
            $v = $input->getOption($name);
            if ($v !== null && (!is_numeric($v) || (int)$v < 0)) {
                $output->writeln('<error>--' . $name . ' must be a number >= 0</error>');
                return Command::INVALID;
            }
            $ints[$name] = $v === null ? $default : (int)$v;
        }

        $this->worker->configure($ints['job-timeout'], $ints['batch-seconds']);
        $log = static function (string $line) use ($output) {
            $output->writeln('[jobs] ' . date('Y-m-d H:i:s') . ' ' . $line);
        };
        if ($output->isVerbose() || !$once) {
            $log(sprintf('worker %s started (job timeout %d s, batch %d s%s)', $this->worker->getWorkerId(), $ints['job-timeout'], $ints['batch-seconds'], $ints['time-limit'] ? ', time limit ' . $ints['time-limit'] . ' s' : ''));
        }
        $runs = $this->worker->work($ints['time-limit'], $ints['memory-limit'], max(1, $ints['sleep']), $once, $log);
        if ($output->isVerbose() || !$once || $runs > 0) {
            $log(sprintf('worker exiting after %d job run(s)', $runs));
        }

        return Command::SUCCESS;
    }

    private static function envInt(?string $value, int $default): int
    {
        return $value !== null && $value !== '' && ctype_digit($value) ? (int)$value : $default;
    }
}
