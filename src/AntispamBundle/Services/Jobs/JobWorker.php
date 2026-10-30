<?php

namespace AntispamBundle\Services\Jobs;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\RuntimeCacheInterface;
use Doctrine\DBAL\Connection;
use Doctrine\Persistence\ManagerRegistry;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;

/**
 * Picks queued jobs and runs them (`antispam:jobs:work`, docs/jobs.md).
 *
 *   - claim: conditional UPDATE queued -> running, so several workers never
 *     run the same job;
 *   - result / error / "continue later" are written when the handler returns;
 *   - a job whose worker died (container restart, OOM, killed by the time
 *     limit) is recovered: its worker process is gone (same host) or its
 *     heartbeat is older than the stale limit -> queued again, failed after
 *     MAX_INTERRUPTIONS;
 *   - every job gets the job time limit (SIGALRM when pcntl is available; the
 *     scheduler's `timeout` around the worker is the hard backstop).
 */
class JobWorker
{
    const MAX_INTERRUPTIONS = 3;
    /** SSH agent scan read timeout (3600 s) + connect + rules push. */
    const DEFAULT_JOB_TIMEOUT = 3900;
    /** Length of one run of a resumable job (big scan) before it yields to other jobs. */
    const DEFAULT_BATCH_SECONDS = 120;
    const MAX_ERROR = 5000;

    /** @var array<string, JobHandlerInterface> */
    private array $handlers = [];
    private int $jobTimeout = self::DEFAULT_JOB_TIMEOUT;
    private int $batchSeconds = self::DEFAULT_BATCH_SECONDS;
    private ?int $staleAfter = null;
    private bool $stopRequested = false;
    private string $workerId;

    public function __construct(
        private Connection $db,
        private ManagerRegistry $doctrine,
        #[AutowireIterator('antispam.job_handler')] iterable $handlers,
        private ?LoggerInterface $logger = null,
        private ?AuditLogger $audit = null,
        /** @var iterable<RuntimeCacheInterface> rules / settings cached for the process lifetime */
        #[AutowireIterator('antispam.runtime_cache')] private iterable $runtimeCaches = [],
    ) {
        foreach ($handlers as $handler) {
            $this->handlers[$handler::type()] = $handler;
        }
        $this->workerId = mb_substr((string)gethostname(), 0, 80) . ':' . getmypid();
    }

    /**
     * @param int      $jobTimeout   seconds one job may run (0 = no limit)
     * @param int      $batchSeconds length of one run of a resumable job
     * @param int|null $staleAfter   seconds without heartbeat after which a running
     *                               job counts as abandoned (default: job timeout + 5 min)
     */
    public function configure(int $jobTimeout, int $batchSeconds, ?int $staleAfter = null): void
    {
        $this->jobTimeout = max(0, $jobTimeout);
        $this->batchSeconds = max(5, $batchSeconds);
        $this->staleAfter = $staleAfter;
    }

    public function getWorkerId(): string
    {
        return $this->workerId;
    }

    /** @return string[] registered job types */
    public function types(): array
    {
        return array_keys($this->handlers);
    }

    public function requestStop(): void
    {
        $this->stopRequested = true;
    }

    /**
     * Loop: recover abandoned jobs, run due jobs, sleep when idle; ends after
     * $timeLimit seconds (no new job is started then), over $memoryLimitMb,
     * on SIGTERM / SIGINT, or - with $once - as soon as the queue is empty.
     *
     * @param callable(string): void|null $log
     *
     * @return int number of job runs
     */
    public function work(int $timeLimit = 0, int $memoryLimitMb = 256, int $sleepSeconds = 2, bool $once = false, ?callable $log = null): int
    {
        $this->stopRequested = false;
        if (\function_exists('pcntl_signal')) {
            pcntl_async_signals(true);
            foreach ([\SIGTERM, \SIGINT] as $signal) {
                pcntl_signal($signal, fn () => $this->requestStop());
            }
        }
        $start = time();
        $runs = 0;
        $this->recoverStale($log);
        while (!$this->stopRequested) {
            if ($timeLimit > 0 && time() - $start >= $timeLimit) {
                break;
            }
            $ran = $this->runNext($log);
            if ($ran !== null) {
                $runs++;
                if ($memoryLimitMb > 0 && memory_get_usage(true) > $memoryLimitMb * 1024 * 1024) {
                    $log && $log('memory limit reached, exiting');
                    break;
                }
                continue;
            }
            if ($once) {
                break;
            }
            // Idle: look for abandoned jobs now and then, otherwise just poll.
            if ($runs === 0 || time() % 60 < $sleepSeconds) {
                $this->recoverStale($log);
            }
            sleep(max(1, $sleepSeconds));
        }
        return $runs;
    }

    /**
     * Runs the next due job, if any.
     *
     * @return array{id:int, status:string}|null null when nothing was due
     */
    public function runNext(?callable $log = null): ?array
    {
        $id = $this->claim();
        if ($id === null) {
            return null;
        }
        $status = $this->process($id, $log);
        return ['id' => $id, 'status' => $status];
    }

    /** Puts jobs whose worker died back into the queue (or fails them after MAX_INTERRUPTIONS). */
    public function recoverStale(?callable $log = null): int
    {
        $staleAfter = $this->staleAfter ?? ($this->jobTimeout > 0 ? $this->jobTimeout + 300 : 7200);
        $limit = time() - $staleAfter;
        $recovered = 0;
        foreach ($this->db->fetchAllAssociative('SELECT id, worker, heartbeat_at, started_at, interruptions FROM ' . BackgroundJob::TABLE . ' WHERE status = ?', [BackgroundJob::STATUS_RUNNING]) as $row) {
            $beat = $row['heartbeat_at'] ?? $row['started_at'];
            $dead = $beat === null || strtotime((string)$beat) < $limit || $this->workerGone((string)$row['worker']);
            if (!$dead) {
                continue;
            }
            $interruptions = (int)$row['interruptions'] + 1;
            if ($interruptions >= self::MAX_INTERRUPTIONS) {
                $n = $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET status = ?, active_key = NULL, interruptions = ?, finished_at = ?, error = ? WHERE id = ? AND status = ? AND ' . self::workerCondition($row['worker']),
                    array_merge([BackgroundJob::STATUS_FAILED, $interruptions, JobQueue::now(), sprintf('Proces wykonujący zadanie został przerwany %d razy (restart, brak pamięci lub przekroczony limit czasu) - zadanie porzucone.', $interruptions), (int)$row['id'], BackgroundJob::STATUS_RUNNING], self::workerParams($row['worker'])));
            } else {
                $n = $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET status = ?, worker = NULL, heartbeat_at = NULL, interruptions = ?, available_at = ?, progress = ? WHERE id = ? AND status = ? AND ' . self::workerCondition($row['worker']),
                    array_merge([BackgroundJob::STATUS_QUEUED, $interruptions, JobQueue::now(), 'Wznowione - poprzedni proces przerwał pracę w trakcie zadania', (int)$row['id'], BackgroundJob::STATUS_RUNNING], self::workerParams($row['worker'])));
            }
            if ($n > 0) {
                $recovered++;
                $log && $log(sprintf('job #%d: worker %s gone, %s', $row['id'], $row['worker'] ?? '?', $interruptions >= self::MAX_INTERRUPTIONS ? 'failed' : 'requeued'));
                $this->logger?->warning('antispam: background job abandoned by its worker', ['job' => (int)$row['id'], 'worker' => $row['worker'], 'interruptions' => $interruptions]);
            }
        }
        return $recovered;
    }

    private static function workerCondition($worker): string
    {
        return $worker === null ? 'worker IS NULL' : 'worker = ?';
    }

    private static function workerParams($worker): array
    {
        return $worker === null ? [] : [(string)$worker];
    }

    /** The worker ran on this host and its process no longer exists (or it is this process). */
    private function workerGone(string $worker): bool
    {
        $pos = strrpos($worker, ':');
        if ($pos === false || !\function_exists('posix_kill')) {
            return false;
        }
        $host = substr($worker, 0, $pos);
        $pid = (int)substr($worker, $pos + 1);
        if ($host !== mb_substr((string)gethostname(), 0, 80) || $pid <= 0) {
            return false;
        }
        if ($pid === getmypid()) {
            return true; // this process is not running it - we are here
        }
        if (@posix_kill($pid, 0)) {
            return false;
        }
        // EPERM: the process exists but belongs to another user.
        return posix_get_last_error() !== 1;
    }

    private function claim(): ?int
    {
        $now = JobQueue::now();
        $ids = $this->db->fetchFirstColumn('SELECT id FROM ' . BackgroundJob::TABLE . ' WHERE status = ? AND available_at <= ? ORDER BY available_at, id LIMIT 10', [BackgroundJob::STATUS_QUEUED, $now]);
        foreach ($ids as $id) {
            $n = $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET status = ?, worker = ?, started_at = COALESCE(started_at, ?), heartbeat_at = ?, attempts = attempts + 1 WHERE id = ? AND status = ?',
                [BackgroundJob::STATUS_RUNNING, $this->workerId, $now, $now, (int)$id, BackgroundJob::STATUS_QUEUED]);
            if ($n > 0) {
                return (int)$id;
            }
        }
        return null;
    }

    private function process(int $id, ?callable $log): string
    {
        $row = $this->db->fetchAssociative('SELECT * FROM ' . BackgroundJob::TABLE . ' WHERE id = ?', [$id]);
        $handler = $this->handlers[$row['type']] ?? null;
        if ($handler === null) {
            $this->finish($id, BackgroundJob::STATUS_FAILED, null, 'Nieznany typ zadania: ' . $row['type']);
            return BackgroundJob::STATUS_FAILED;
        }
        if (!$handler::exclusive()) {
            $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET active_key = NULL WHERE id = ?', [$id]);
        }
        if ((int)$row['cancel_requested']) {
            $this->finish($id, BackgroundJob::STATUS_CANCELLED, null, 'Anulowane.');
            return BackgroundJob::STATUS_CANCELLED;
        }

        $context = new JobContext(
            $this->db, $id, (string)$row['type'], self::decode($row['payload']), self::decode($row['state']),
            $row['account_id'] !== null ? (int)$row['account_id'] : null, $row['mailbox'], $row['requested_by'], $row['requested_by_type'],
            microtime(true) + $this->batchSeconds, $this->audit,
        );
        $log && $log(sprintf('job #%d %s (%s) started', $id, $row['type'], $row['label']));
        $started = microtime(true);

        // Every job (and every batch of a resumable one) sees the rules and
        // settings as they are now, not as when this worker started.
        foreach ($this->runtimeCaches as $cache) {
            $cache->clearRuntimeCache();
        }

        $this->armTimeout($id);
        try {
            $result = $handler->handle($context);
            $error = null;
        } catch (\Throwable $e) {
            $result = null;
            $error = $e->getMessage() !== '' ? $e->getMessage() : get_class($e);
            $this->logger?->error('antispam: background job failed', ['job' => $id, 'type' => $row['type'], 'exception' => $e]);
        } finally {
            $this->disarmTimeout();
        }

        $continuation = $context->continuation();
        if ($error !== null) {
            $status = BackgroundJob::STATUS_FAILED;
            $this->finish($id, $status, null, $error);
        } elseif ($continuation !== null) {
            [$state, $delay, $progress] = $continuation;
            if ($context->isCancelRequested()) {
                $status = BackgroundJob::STATUS_CANCELLED;
                $this->finish($id, $status, $state['result'] ?? null, 'Anulowane w trakcie - wykonana część została zachowana.');
            } else {
                $status = BackgroundJob::STATUS_QUEUED;
                $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET status = ?, state = ?, worker = NULL, heartbeat_at = NULL, available_at = ?' . ($progress !== null ? ', progress = ?' : '') . ' WHERE id = ?',
                    array_merge([$status, self::encode($state), (new \DateTime('+' . $delay . ' seconds'))->format('Y-m-d H:i:s')], $progress !== null ? [mb_substr($progress, 0, 255)] : [], [$id]));
            }
        } else {
            $status = BackgroundJob::STATUS_DONE;
            $this->finish($id, $status, $result, null);
        }
        $log && $log(sprintf('job #%d %s: %s in %.1f s%s', $id, $row['type'], $status === BackgroundJob::STATUS_QUEUED ? 'continues later' : $status, microtime(true) - $started, $error !== null ? ' - ' . $error : ''));

        $this->resetDoctrine();
        return $status;
    }

    /** Final state; frees the dedupe key. */
    private function finish(int $id, string $status, ?array $result, ?string $error): void
    {
        $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET status = ?, active_key = NULL, result = ?, error = ?, finished_at = ?, heartbeat_at = ? WHERE id = ?', [
            $status,
            $result === null ? null : self::encode($result),
            $error === null ? null : mb_substr($error, 0, self::MAX_ERROR),
            JobQueue::now(), JobQueue::now(), $id,
        ]);
    }

    private function armTimeout(int $id): void
    {
        if ($this->jobTimeout <= 0 || !\function_exists('pcntl_alarm')) {
            return;
        }
        pcntl_async_signals(true);
        pcntl_signal(\SIGALRM, function () use ($id) {
            try {
                $this->finish($id, BackgroundJob::STATUS_FAILED, null, sprintf('Przekroczono limit czasu zadania (%d s) - przerwano.', $this->jobTimeout));
            } finally {
                $this->logger?->error('antispam: background job killed by its time limit', ['job' => $id, 'timeout' => $this->jobTimeout]);
                // The handler may be stuck anywhere: end the process, the scheduler starts a new worker.
                exit(1);
            }
        });
        pcntl_alarm($this->jobTimeout);
    }

    private function disarmTimeout(): void
    {
        if (\function_exists('pcntl_alarm')) {
            pcntl_alarm(0);
        }
    }

    /** Fresh unit of work for the next job; a closed EntityManager (failed flush) is replaced. */
    private function resetDoctrine(): void
    {
        try {
            $em = $this->doctrine->getManager();
            if (!$em->isOpen()) {
                $this->doctrine->resetManager();
            } else {
                $em->clear();
            }
        } catch (\Throwable $e) {
            $this->logger?->warning('antispam: could not reset the entity manager after a job', ['exception' => $e]);
        }
    }

    private static function encode(array $data): string
    {
        return (string)json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }

    private static function decode($json): array
    {
        $data = is_string($json) && $json !== '' ? json_decode($json, true) : null;
        return is_array($data) ? $data : [];
    }
}
