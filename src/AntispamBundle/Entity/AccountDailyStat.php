<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Scan counters of one mailbox account per day and kind ("Statystyki konta",
 * docs/account-stats.md). Written after every scan / rescan pass by
 * AccountStatsService::record() - IMAP and SSH alike, so SSH accounts (whose
 * per-message log stays in the agent) have the same totals. Never pruned:
 * one row per account, day and kind.
 */
#[ORM\Entity]
#[ORM\Table(name: 'antispam_account_daily_stat')]
#[ORM\UniqueConstraint(name: 'uniq_account_day_kind', columns: ['account_id', 'day', 'kind'])]
class AccountDailyStat
{
    /** Scheduled / panel scan of new mail. */
    public const KIND_SCAN = 'scan';
    /** First scan of a newly connected mailbox (old mail clean-up). */
    public const KIND_INITIAL = 'initial';
    /** Full rescan against the current rules. */
    public const KIND_RESCAN = 'rescan';
    /** Retroactive pass after a new blacklist rule. */
    public const KIND_RETRO = 'retro';

    public const KINDS = [
        self::KIND_SCAN => 'skany nowej poczty',
        self::KIND_INITIAL => 'pierwszy skan',
        self::KIND_RESCAN => 'ponowne skanowanie',
        self::KIND_RETRO => 'wstecz po nowej regule',
    ];

    /** Counters summed per row (keys of the scan result). */
    public const COUNTERS = ['passes', 'checked', 'skipped', 'whitelisted', 'blacklisted', 'quarantined', 'moved_to_spam', 'move_failed', 'errors'];

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private ?int $id = null;

    #[ORM\Column(name: 'account_id', type: 'integer')]
    private int $accountId;

    #[ORM\Column(name: 'day', type: 'date_immutable')]
    private \DateTimeImmutable $day;

    #[ORM\Column(name: 'kind', type: 'string', length: 16)]
    private string $kind;

    #[ORM\Column(name: 'passes', type: 'integer')]
    private int $passes = 0;

    #[ORM\Column(name: 'checked', type: 'integer')]
    private int $checked = 0;

    #[ORM\Column(name: 'skipped', type: 'integer')]
    private int $skipped = 0;

    #[ORM\Column(name: 'whitelisted', type: 'integer')]
    private int $whitelisted = 0;

    #[ORM\Column(name: 'blacklisted', type: 'integer')]
    private int $blacklisted = 0;

    #[ORM\Column(name: 'quarantined', type: 'integer')]
    private int $quarantined = 0;

    #[ORM\Column(name: 'moved_to_spam', type: 'integer')]
    private int $movedToSpam = 0;

    #[ORM\Column(name: 'move_failed', type: 'integer')]
    private int $moveFailed = 0;

    #[ORM\Column(name: 'errors', type: 'integer')]
    private int $errors = 0;

    #[ORM\Column(name: 'updated_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $updatedAt;

    public function __construct(int $accountId, \DateTimeImmutable $day, string $kind)
    {
        $this->accountId = $accountId;
        $this->day = $day->setTime(0, 0);
        $this->kind = $kind;
        $this->updatedAt = new \DateTimeImmutable();
    }

    public function getId(): ?int { return $this->id; }
    public function getAccountId(): int { return $this->accountId; }
    public function getDay(): \DateTimeImmutable { return $this->day; }
    public function getKind(): string { return $this->kind; }
    public function getUpdatedAt(): \DateTimeImmutable { return $this->updatedAt; }

    /** @return array<string, int> */
    public function counters(): array
    {
        return [
            'passes' => $this->passes, 'checked' => $this->checked, 'skipped' => $this->skipped,
            'whitelisted' => $this->whitelisted, 'blacklisted' => $this->blacklisted, 'quarantined' => $this->quarantined,
            'moved_to_spam' => $this->movedToSpam, 'move_failed' => $this->moveFailed, 'errors' => $this->errors,
        ];
    }

    /** @param array<string, int> $add */
    public function add(array $add): self
    {
        $this->passes += (int)($add['passes'] ?? 0);
        $this->checked += (int)($add['checked'] ?? 0);
        $this->skipped += (int)($add['skipped'] ?? 0);
        $this->whitelisted += (int)($add['whitelisted'] ?? 0);
        $this->blacklisted += (int)($add['blacklisted'] ?? 0);
        $this->quarantined += (int)($add['quarantined'] ?? 0);
        $this->movedToSpam += (int)($add['moved_to_spam'] ?? 0);
        $this->moveFailed += (int)($add['move_failed'] ?? 0);
        $this->errors += (int)($add['errors'] ?? 0);
        $this->updatedAt = new \DateTimeImmutable();
        return $this;
    }
}
