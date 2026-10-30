<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\User;
use AntispamBundle\Services\Jobs\EnqueueResult;
use AntispamBundle\Services\Jobs\JobQueue;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Queues "Usuń wszystkie wysokiego ryzyka" / "Usuń wszystko z kwarantanny" of
 * one mailbox as a background job (quarantine.purge, handled by
 * Jobs\Handler\QuarantinePurgeHandler -> QuarantineService::purge()).
 *
 * Dedupe key `quarantine.purge:<mailbox key>:<mode>`: one purge per mailbox
 * and mode while it is queued or running. Ownership is checked by the caller
 * (SpamboxController = admin, MyController = MailboxAccess) and again by the
 * handler when it runs.
 */
class QuarantinePurge
{
    const SOURCE_PANEL = 'panel';
    const SOURCE_MY = 'my';

    const MODE_LABELS = [
        QuarantineService::PURGE_HIGH_RISK => 'wiadomości wysokiego ryzyka',
        QuarantineService::PURGE_ALL => 'wszystkie wiadomości',
        QuarantineService::PURGE_MIN_SCORE => 'wiadomości z wynikiem od N pkt',
    ];
    /** Highest threshold accepted from the form ("od N pkt"). */
    const MAX_MIN_SCORE = 1000;

    public function __construct(
        private JobQueue $jobs,
        private EntityManagerInterface $em,
        private ?AuditLogger $audit = null,
    ) {
    }

    public static function dedupeKey(string $key, string $mode): string
    {
        return BackgroundJob::TYPE_QUARANTINE_PURGE . ':' . $key . ':' . $mode;
    }

    public static function isMode(string $mode): bool
    {
        return in_array($mode, QuarantineService::PURGE_MODES, true);
    }

    /**
     * @param array            $mailbox   a QuarantineService::getMailboxes() row
     * @param int|null         $shown     how many messages (of this mode) the page showed - for the job page and audit only
     * @param UserInterface|null $requester a database user is stored as the job's requester (the user area shows only own jobs)
     * @param int|null         $minScore  PURGE_MIN_SCORE: delete messages whose score is at least this (1-MAX_MIN_SCORE)
     */
    public function enqueue(array $mailbox, string $mode, string $source, ?int $shown = null, ?UserInterface $requester = null, ?int $minScore = null): EnqueueResult
    {
        if (!self::isMode($mode)) {
            throw new \InvalidArgumentException('Unknown quarantine purge mode: ' . $mode);
        }
        $byScore = $mode === QuarantineService::PURGE_MIN_SCORE;
        if ($byScore && ($minScore === null || $minScore < 1 || $minScore > self::MAX_MIN_SCORE)) {
            throw new \InvalidArgumentException('Quarantine purge by score needs a threshold of 1-' . self::MAX_MIN_SCORE);
        }
        $key = (string)$mailbox['key'];
        $account = preg_match('/^(imap|ssh)-(\d+)\z/', $key, $m) ? $this->em->find(Account::class, (int)$m[2]) : null;
        $requestedBy = $requester instanceof User ? (string)$requester->getUsername() : null;

        $queued = $this->jobs->enqueue(
            BackgroundJob::TYPE_QUARANTINE_PURGE,
            ['key' => $key, 'mode' => $mode, 'source' => $source, 'shown' => $shown] + ($byScore ? ['min_score' => $minScore] : []),
            $account,
            label: match ($mode) {
                QuarantineService::PURGE_ALL => 'Usuń wszystko z kwarantanny: ',
                QuarantineService::PURGE_MIN_SCORE => 'Usuń z kwarantanny wiadomości od ' . $minScore . ' pkt: ',
                default => 'Usuń wysokiego ryzyka z kwarantanny: ',
            } . (string)$mailbox['label'],
            dedupeKey: self::dedupeKey($key, $mode),
            mailbox: ((string)($mailbox['account_email'] ?? '')) ?: null,
            requestedBy: $requestedBy,
            requestedByType: $requestedBy !== null ? AuditLog::ACTOR_USER : null,
        );
        if ($queued->created) {
            $this->audit?->log('quarantine.purge_queued', targetType: 'quarantine', targetId: $key, label: (string)$mailbox['label'],
                mailbox: ((string)($mailbox['account_email'] ?? '')) ?: null,
                details: ['job' => $queued->id, 'mode' => $mode, 'source' => $source, 'shown' => $shown] + ($byScore ? ['min_score' => $minScore] : []));
        }
        return $queued;
    }
}
