<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\BackgroundJobRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * One heavy panel operation (scan, agent deploy, rules sync, retroactive rule
 * pass, CERT sync...) queued for the background worker (`antispam:jobs:work`)
 * instead of running inside the HTTP request. See docs/jobs.md.
 *
 * State changes are written with plain DBAL by Services\Jobs\JobQueue and
 * JobWorker (never through the unit of work), so this entity is read-only
 * for the rest of the app.
 *
 * `active_key` = the dedupe key while the job is queued (and, for exclusive
 * job types, running), NULL otherwise. Its unique index makes "do not queue a
 * second scan of the same mailbox" race-free.
 */
#[ORM\Entity(repositoryClass: BackgroundJobRepository::class)]
#[ORM\Table(name: 'antispam_job')]
#[ORM\Index(name: 'idx_job_status_available', columns: ['status', 'available_at'])]
#[ORM\Index(name: 'idx_job_account', columns: ['account_id'])]
#[ORM\Index(name: 'idx_job_created', columns: ['created_at'])]
#[ORM\UniqueConstraint(name: 'uniq_job_active_key', columns: ['active_key'])]
class BackgroundJob
{
    const TABLE = 'antispam_job';

    const STATUS_QUEUED = 'queued';
    const STATUS_RUNNING = 'running';
    const STATUS_DONE = 'done';
    const STATUS_FAILED = 'failed';
    const STATUS_CANCELLED = 'cancelled';

    const STATUSES = [
        self::STATUS_QUEUED => 'w kolejce',
        self::STATUS_RUNNING => 'trwa',
        self::STATUS_DONE => 'zakończone',
        self::STATUS_FAILED => 'błąd',
        self::STATUS_CANCELLED => 'anulowane',
    ];

    const ACTIVE_STATUSES = [self::STATUS_QUEUED, self::STATUS_RUNNING];

    /** Job types (Services\Jobs\Handler\*) with their Polish labels. */
    const TYPE_ACCOUNT_SCAN = 'account.scan';
    const TYPE_ACCOUNT_RESCAN = 'account.rescan';
    const TYPE_ACCOUNT_DEPLOY = 'account.deploy';
    const TYPE_ACCOUNT_SYNC = 'account.sync';
    const TYPE_ACCOUNT_HEALTH = 'account.health';
    const TYPE_RULE_RETROACTIVE = 'rule.retroactive';
    const TYPE_CERT_SYNC = 'cert.sync';
    const TYPE_DIGEST_SEND = 'digest.send';
    const TYPE_PHISHING_FORWARD = 'phishing.forward';
    const TYPE_HEALTH_FULL = 'health.full';

    const TYPES = [
        self::TYPE_ACCOUNT_SCAN => 'Skanowanie skrzynki',
        self::TYPE_ACCOUNT_RESCAN => 'Ponowny skan całej skrzynki',
        self::TYPE_ACCOUNT_DEPLOY => 'Wdrożenie agenta',
        self::TYPE_ACCOUNT_SYNC => 'Synchronizacja reguł',
        self::TYPE_ACCOUNT_HEALTH => 'Stan agenta',
        self::TYPE_RULE_RETROACTIVE => 'Nowa reguła: istniejąca poczta',
        self::TYPE_CERT_SYNC => 'Synchronizacja listy CERT',
        self::TYPE_DIGEST_SEND => 'Raport kwarantanny: wysyłka',
        self::TYPE_PHISHING_FORWARD => 'Phishing: wysyłka zgłoszeń',
        self::TYPE_HEALTH_FULL => 'Pełne sprawdzenie stanu',
    ];

    /** Finished jobs older than this are deleted by antispam:purge (config `jobs.retention_days`). */
    const CONFIG_RETENTION = 'jobs.retention_days';
    const DEFAULT_RETENTION_DAYS = 30;

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'type', type: 'string', length: 50)]
    private $type;

    #[ORM\Column(name: 'status', type: 'string', length: 16)]
    private $status = self::STATUS_QUEUED;

    /** JSON */
    #[ORM\Column(name: 'payload', type: 'text', nullable: true)]
    private $payload;

    /** Plain id, no foreign key: a deleted account must not delete its job history. */
    #[ORM\Column(name: 'account_id', type: 'integer', nullable: true)]
    private $accountId;

    /** Mailbox address the job is about (display, ownership). */
    #[ORM\Column(name: 'mailbox', type: 'string', length: 255, nullable: true)]
    private $mailbox;

    #[ORM\Column(name: 'label', type: 'string', length: 255)]
    private $label = '';

    #[ORM\Column(name: 'dedupe_key', type: 'string', length: 190, nullable: true)]
    private $dedupeKey;

    #[ORM\Column(name: 'active_key', type: 'string', length: 190, nullable: true)]
    private $activeKey;

    #[ORM\Column(name: 'requested_by', type: 'string', length: 180, nullable: true)]
    private $requestedBy;

    /** AuditLog::ACTOR_* of the requester */
    #[ORM\Column(name: 'requested_by_type', type: 'string', length: 20, nullable: true)]
    private $requestedByType;

    #[ORM\Column(name: 'progress', type: 'string', length: 255, nullable: true)]
    private $progress;

    #[ORM\Column(name: 'progress_done', type: 'integer', nullable: true)]
    private $progressDone;

    #[ORM\Column(name: 'progress_total', type: 'integer', nullable: true)]
    private $progressTotal;

    /** JSON - what a resumable job (big scan) has done so far, kept between runs. */
    #[ORM\Column(name: 'state', type: 'text', nullable: true)]
    private $state;

    /** JSON - handler result, rendered on the job page. */
    #[ORM\Column(name: 'result', type: 'text', nullable: true)]
    private $result;

    #[ORM\Column(name: 'error', type: 'text', nullable: true)]
    private $error;

    /** How many times a worker picked the job up (a resumed scan counts every run). */
    #[ORM\Column(name: 'attempts', type: 'integer', options: ['default' => 0])]
    private $attempts = 0;

    /** How many times the worker died while running it (stale recovery). */
    #[ORM\Column(name: 'interruptions', type: 'integer', options: ['default' => 0])]
    private $interruptions = 0;

    #[ORM\Column(name: 'cancel_requested', type: 'boolean', options: ['default' => false])]
    private $cancelRequested = false;

    /** host:pid of the worker running it */
    #[ORM\Column(name: 'worker', type: 'string', length: 100, nullable: true)]
    private $worker;

    #[ORM\Column(name: 'created_at', type: 'datetime')]
    private $createdAt;

    /** Not picked up before this time (a scan waiting for the scheduled scan to release the mailbox). */
    #[ORM\Column(name: 'available_at', type: 'datetime')]
    private $availableAt;

    #[ORM\Column(name: 'started_at', type: 'datetime', nullable: true)]
    private $startedAt;

    #[ORM\Column(name: 'finished_at', type: 'datetime', nullable: true)]
    private $finishedAt;

    #[ORM\Column(name: 'heartbeat_at', type: 'datetime', nullable: true)]
    private $heartbeatAt;

    public function __construct(string $type = '')
    {
        $this->type = $type;
        $this->createdAt = new \DateTime();
        $this->availableAt = new \DateTime();
    }

    public function getId() { return $this->id; }
    public function getType() { return $this->type; }
    public function getTypeLabel() { return self::TYPES[$this->type] ?? $this->type; }
    public function getStatus() { return $this->status; }
    public function getStatusLabel() { return self::STATUSES[$this->status] ?? $this->status; }
    public function getAccountId() { return $this->accountId; }
    public function getMailbox() { return $this->mailbox; }
    public function getLabel() { return $this->label; }
    public function getDedupeKey() { return $this->dedupeKey; }
    public function getActiveKey() { return $this->activeKey; }
    public function getRequestedBy() { return $this->requestedBy; }
    public function getRequestedByType() { return $this->requestedByType; }
    public function getProgress() { return $this->progress; }
    public function getProgressDone() { return $this->progressDone; }
    public function getProgressTotal() { return $this->progressTotal; }
    public function getError() { return $this->error; }
    public function getAttempts() { return (int)$this->attempts; }
    public function getInterruptions() { return (int)$this->interruptions; }
    public function isCancelRequested() { return (bool)$this->cancelRequested; }
    public function getWorker() { return $this->worker; }
    public function getCreatedAt() { return $this->createdAt; }
    public function getAvailableAt() { return $this->availableAt; }
    public function getStartedAt() { return $this->startedAt; }
    public function getFinishedAt() { return $this->finishedAt; }
    public function getHeartbeatAt() { return $this->heartbeatAt; }

    public function getPayload(): array
    {
        return self::decode($this->payload);
    }

    public function getState(): array
    {
        return self::decode($this->state);
    }

    public function getResult(): ?array
    {
        return $this->result === null ? null : self::decode($this->result);
    }

    public function isActive(): bool
    {
        return in_array($this->status, self::ACTIVE_STATUSES, true);
    }

    public function isFinished(): bool
    {
        return !$this->isActive();
    }

    /** Progress in percent (0-100), null when the total is unknown. */
    public function getPercent(): ?int
    {
        if (!$this->progressTotal) {
            return null;
        }
        return (int)max(0, min(100, floor(100 * (int)$this->progressDone / (int)$this->progressTotal)));
    }

    /** Seconds from the first start to the end (or now), null before the first start. */
    public function getDuration(): ?int
    {
        if (!$this->startedAt) {
            return null;
        }
        $end = $this->finishedAt ?: new \DateTime();
        return max(0, $end->getTimestamp() - $this->startedAt->getTimestamp());
    }

    private static function decode($json): array
    {
        if (!is_string($json) || $json === '') {
            return [];
        }
        $data = json_decode($json, true);
        return is_array($data) ? $data : [];
    }
}
