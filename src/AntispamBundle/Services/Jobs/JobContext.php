<?php

namespace AntispamBundle\Services\Jobs;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AuditLogger;
use Doctrine\DBAL\Connection;

/**
 * What a JobHandlerInterface sees of the job it runs: payload, the state kept
 * from a previous run, progress / heartbeat reporting, cancellation and the
 * "continue in another run" request. Created by JobWorker for every run.
 */
class JobContext
{
    private ?array $continueState = null;
    private int $continueDelay = 0;
    private ?string $continueProgress = null;
    private float $lastBeat;

    public function __construct(
        private Connection $db,
        private int $jobId,
        private string $type,
        private array $payload,
        private array $state,
        private ?int $accountId,
        private ?string $mailbox,
        private ?string $requestedBy,
        private ?string $requestedByType,
        /** microtime(true) by which a resumable handler should stop and continueLater() */
        private float $batchDeadline,
        private ?AuditLogger $audit = null,
    ) {
        $this->lastBeat = microtime(true);
    }

    public function jobId(): int { return $this->jobId; }
    public function type(): string { return $this->type; }
    public function payload(): array { return $this->payload; }
    public function state(): array { return $this->state; }
    public function accountId(): ?int { return $this->accountId; }
    public function mailbox(): ?string { return $this->mailbox; }
    public function requestedBy(): ?string { return $this->requestedBy; }
    public function batchDeadline(): float { return $this->batchDeadline; }

    /** Progress text (+ counters) shown on the job page; also a heartbeat. */
    public function progress(string $text, ?int $done = null, ?int $total = null): void
    {
        $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET progress = ?, progress_done = ?, progress_total = ?, heartbeat_at = ? WHERE id = ?',
            [mb_substr($text, 0, 255), $done, $total, JobQueue::now(), $this->jobId]);
        $this->lastBeat = microtime(true);
    }

    /** "Still alive" for the stale-job recovery; cheap, at most one write per 10 s. */
    public function heartbeat(): void
    {
        if (microtime(true) - $this->lastBeat < 10) {
            return;
        }
        $this->db->executeStatement('UPDATE ' . BackgroundJob::TABLE . ' SET heartbeat_at = ? WHERE id = ?', [JobQueue::now(), $this->jobId]);
        $this->lastBeat = microtime(true);
    }

    public function isCancelRequested(): bool
    {
        return (bool)$this->db->fetchOne('SELECT cancel_requested FROM ' . BackgroundJob::TABLE . ' WHERE id = ?', [$this->jobId]);
    }

    /**
     * End this run and put the job back into the queue with $state (read back
     * through state() in the next run). The handler's return value is ignored
     * then. A cancel request turns it into "cancelled" instead.
     */
    public function continueLater(array $state, int $delaySeconds = 0, ?string $progress = null): void
    {
        $this->continueState = $state;
        $this->continueDelay = max(0, $delaySeconds);
        $this->continueProgress = $progress;
    }

    /** @return array{0: array, 1: int, 2: ?string}|null state, delay, progress */
    public function continuation(): ?array
    {
        return $this->continueState === null ? null : [$this->continueState, $this->continueDelay, $this->continueProgress];
    }

    /** Audit log entry on behalf of whoever requested the job (docs/audit.md). */
    public function audit(string $action, mixed ...$args): void
    {
        if (!$this->audit) {
            return;
        }
        $args['details'] = ($args['details'] ?? []) + ['job' => $this->jobId];
        $args['actor'] = $this->requestedBy ?? 'cli';
        $args['actorType'] = $this->requestedByType ?? 'cli';
        $this->audit->log($action, ...$args);
    }
}
