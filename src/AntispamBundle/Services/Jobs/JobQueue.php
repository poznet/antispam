<?php

namespace AntispamBundle\Services\Jobs;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AuditLogger;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;

/**
 * The background job queue (table antispam_job, docs/jobs.md): the panel
 * enqueues heavy work here and answers at once; `antispam:jobs:work` runs it.
 *
 * Writes use plain DBAL (no unit of work): enqueueing never flushes the
 * caller's pending entity changes, and the worker's state changes are
 * single-row conditional UPDATEs, safe with several workers.
 *
 * Dedupe: a job with a dedupe key holds it in `active_key` (unique index)
 * while queued - and while running, for exclusive types - so the same scan
 * cannot be queued twice; enqueue() then returns the existing job.
 */
class JobQueue
{
    /** A queued job older than this means no worker picks jobs up (health check). */
    const STUCK_WARN_MINUTES = 10;
    const STUCK_FAIL_MINUTES = 60;

    public function __construct(
        private Connection $db,
        private EntityManagerInterface $em,
        private ?AuditLogger $audit = null,
    ) {
    }

    public static function now(): string
    {
        return (new \DateTime())->format('Y-m-d H:i:s');
    }

    /**
     * @param string|null $requestedBy     actor shown on the job (default: the current user, like the audit log)
     * @param string|null $requestedByType AuditLog::ACTOR_*
     */
    public function enqueue(
        string $type,
        array $payload = [],
        ?Account $account = null,
        ?string $label = null,
        ?string $dedupeKey = null,
        ?string $mailbox = null,
        ?string $requestedBy = null,
        ?string $requestedByType = null,
    ): EnqueueResult {
        if ($requestedBy === null) {
            [$requestedBy, $requestedByType] = $this->audit ? $this->audit->currentActor() : [PHP_SAPI === 'cli' ? 'cli' : 'anonymous', PHP_SAPI === 'cli' ? AuditLog::ACTOR_CLI : AuditLog::ACTOR_ANONYMOUS];
        }
        $now = self::now();
        $row = [
            'type' => mb_substr($type, 0, 50),
            'status' => BackgroundJob::STATUS_QUEUED,
            'payload' => $payload ? json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null,
            'account_id' => $account?->getId(),
            'mailbox' => self::cut($mailbox ?? $account?->getEmail(), 255),
            'label' => (string)self::cut($label ?? (BackgroundJob::TYPES[$type] ?? $type), 255),
            'dedupe_key' => self::cut($dedupeKey, 190),
            'active_key' => self::cut($dedupeKey, 190),
            'requested_by' => self::cut($requestedBy, 180),
            'requested_by_type' => self::cut($requestedByType, 20),
            'attempts' => 0,
            'interruptions' => 0,
            'cancel_requested' => 0,
            'created_at' => $now,
            'available_at' => $now,
        ];

        for ($try = 0; $try < 3; $try++) {
            try {
                $this->db->insert(BackgroundJob::TABLE, $row);
                return new EnqueueResult((int)$this->db->lastInsertId(), true);
            } catch (UniqueConstraintViolationException $e) {
                $existing = $this->db->fetchAssociative('SELECT id, status FROM ' . BackgroundJob::TABLE . ' WHERE active_key = ?', [$row['active_key']]);
                if ($existing) {
                    return new EnqueueResult((int)$existing['id'], false, (string)$existing['status']);
                }
                // It finished in between: try again.
            }
        }
        throw new \RuntimeException('Nie udało się dodać zadania do kolejki.');
    }

    /** Fresh copy of a job (the worker writes with DBAL, so the identity map may be stale). */
    public function find(int $id): ?BackgroundJob
    {
        $job = $this->em->find(BackgroundJob::class, $id);
        if ($job) {
            $this->em->refresh($job);
        }
        return $job;
    }

    /** Active (queued / running) job holding a dedupe key, if any. */
    public function findActive(string $dedupeKey): ?int
    {
        $id = $this->db->fetchOne('SELECT id FROM ' . BackgroundJob::TABLE . ' WHERE dedupe_key = ? AND status IN (?, ?) ORDER BY id DESC', [$dedupeKey, BackgroundJob::STATUS_QUEUED, BackgroundJob::STATUS_RUNNING]);
        return $id === false ? null : (int)$id;
    }

    /**
     * A job of $type for the account is running, or queued and due within the
     * last STUCK_FAIL_MINUTES. An older queued job means no worker is running:
     * callers (scan-all) must not wait for it forever.
     */
    public function hasActive(string $type, int $accountId): bool
    {
        $fresh = (new \DateTime('-' . self::STUCK_FAIL_MINUTES . ' minutes'))->format('Y-m-d H:i:s');
        return (bool)$this->db->fetchOne('SELECT 1 FROM ' . BackgroundJob::TABLE . ' WHERE type = ? AND account_id = ? AND (status = ? OR (status = ? AND available_at >= ?))',
            [$type, $accountId, BackgroundJob::STATUS_RUNNING, BackgroundJob::STATUS_QUEUED, $fresh]);
    }

    /**
     * Active jobs per account (account list badges).
     *
     * @return array<int, list<array{id:int, type:string, status:string, label:string, progress:?string}>>
     */
    public function activeByAccount(): array
    {
        $out = [];
        foreach ($this->db->fetchAllAssociative('SELECT id, type, status, label, progress, account_id FROM ' . BackgroundJob::TABLE . ' WHERE account_id IS NOT NULL AND status IN (?, ?) ORDER BY id', [BackgroundJob::STATUS_QUEUED, BackgroundJob::STATUS_RUNNING]) as $r) {
            $out[(int)$r['account_id']][] = [
                'id' => (int)$r['id'], 'type' => (string)$r['type'], 'status' => (string)$r['status'],
                'label' => (string)$r['label'], 'progress' => $r['progress'],
            ];
        }
        return $out;
    }

    /**
     * Cancel a job: a queued one at once, a running one at its next check
     * (a batched scan between two batches; a single long command cannot be
     * interrupted and finishes).
     *
     * @return string|null new state: cancelled / cancel_requested, null = already finished
     */
    public function cancel(int $id): ?string
    {
        $n = $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET status = ?, active_key = NULL, finished_at = ?, error = ? WHERE id = ? AND status = ?',
            [BackgroundJob::STATUS_CANCELLED, self::now(), 'Anulowane przed uruchomieniem.', $id, BackgroundJob::STATUS_QUEUED]);
        if ($n > 0) {
            return BackgroundJob::STATUS_CANCELLED;
        }
        $n = $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET cancel_requested = 1 WHERE id = ? AND status = ?', [$id, BackgroundJob::STATUS_RUNNING]);
        return $n > 0 ? 'cancel_requested' : null;
    }

    /**
     * Queue facts for the health checks / doctor.
     *
     * @return array{queued:int, running:int, oldest_queued_at:?\DateTimeImmutable, failed_24h:int, last_failed:?array}
     */
    public function stats(?\DateTimeImmutable $now = null): array
    {
        $now = $now ?? new \DateTimeImmutable();
        $counts = ['queued' => 0, 'running' => 0];
        foreach ($this->db->fetchAllAssociative('SELECT status, COUNT(*) AS n FROM ' . BackgroundJob::TABLE . ' WHERE status IN (?, ?) GROUP BY status', [BackgroundJob::STATUS_QUEUED, BackgroundJob::STATUS_RUNNING]) as $r) {
            $counts[$r['status']] = (int)$r['n'];
        }
        // Only jobs that could have run: a scan waiting for the scheduled scan has a later available_at.
        $oldest = $this->db->fetchOne('SELECT MIN(available_at) FROM ' . BackgroundJob::TABLE . ' WHERE status = ? AND available_at <= ?', [BackgroundJob::STATUS_QUEUED, $now->format('Y-m-d H:i:s')]);
        $since = $now->modify('-24 hours')->format('Y-m-d H:i:s');
        $failed = (int)$this->db->fetchOne('SELECT COUNT(*) FROM ' . BackgroundJob::TABLE . ' WHERE status = ? AND finished_at >= ?', [BackgroundJob::STATUS_FAILED, $since]);
        $last = $failed ? $this->db->fetchAssociative('SELECT id, type, label, error, finished_at FROM ' . BackgroundJob::TABLE . ' WHERE status = ? AND finished_at >= ? ORDER BY finished_at DESC, id DESC', [BackgroundJob::STATUS_FAILED, $since]) : false;

        return [
            'queued' => $counts['queued'],
            'running' => $counts['running'],
            'oldest_queued_at' => $oldest ? new \DateTimeImmutable((string)$oldest) : null,
            'failed_24h' => $failed,
            'last_failed' => $last ?: null,
        ];
    }

    /** Deletes finished jobs older than $before; active ones are never deleted. */
    public function purgeFinishedBefore(\DateTimeInterface $before): int
    {
        return (int)$this->db->executeStatement('DELETE FROM ' . BackgroundJob::TABLE . ' WHERE status IN (?, ?, ?) AND created_at < ?',
            [BackgroundJob::STATUS_DONE, BackgroundJob::STATUS_FAILED, BackgroundJob::STATUS_CANCELLED, $before->format('Y-m-d H:i:s')]);
    }

    public function countFinishedBefore(\DateTimeInterface $before): int
    {
        return (int)$this->db->fetchOne('SELECT COUNT(*) FROM ' . BackgroundJob::TABLE . ' WHERE status IN (?, ?, ?) AND created_at < ?',
            [BackgroundJob::STATUS_DONE, BackgroundJob::STATUS_FAILED, BackgroundJob::STATUS_CANCELLED, $before->format('Y-m-d H:i:s')]);
    }

    private static function cut(?string $value, int $length): ?string
    {
        return $value === null ? null : mb_substr($value, 0, $length);
    }
}
