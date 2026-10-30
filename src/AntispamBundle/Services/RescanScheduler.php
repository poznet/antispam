<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\Jobs\EnqueueResult;
use AntispamBundle\Services\Jobs\JobQueue;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Queues full rescans of a mailbox (job `account.rescan`, see
 * Jobs\Handler\AccountRescanHandler) - from the panel button and from the
 * weekly schedule (`antispam:rescan:due`, hourly through antispam:cron:run).
 *
 * Dedupe key `account.rescan:<account id>`: one rescan per account while it is
 * queued or running (exclusive job type).
 *
 * Weekly schedule: an account with auto rescan on is due when its slot of
 * this week (ISO day + hour, server time) has started, less than
 * DUE_WINDOW_HOURS ago, and no rescan ended after the slot started. A rescan
 * that failed still counts as done for that week (its error is shown on the
 * account list); a scheduler that was down for longer than the window skips
 * that week instead of rescanning at a random time of day.
 */
class RescanScheduler
{
    const DUE_WINDOW_HOURS = 24;
    const TRIGGER_PANEL = 'panel';
    const TRIGGER_SCHEDULE = 'schedule';
    const TRIGGER_CLI = 'cli';
    const TRIGGER_PLUGIN = 'plugin';
    const TRIGGERS = [self::TRIGGER_PANEL => 'panel', self::TRIGGER_SCHEDULE => 'harmonogram (co tydzień)', self::TRIGGER_CLI => 'konsola', self::TRIGGER_PLUGIN => 'wtyczka pocztowa'];

    public function __construct(
        private EntityManagerInterface $em,
        private JobQueue $jobs,
        private ?AuditLogger $audit = null,
    ) {
    }

    public static function dedupeKey(Account $account): string
    {
        return BackgroundJob::TYPE_ACCOUNT_RESCAN . ':' . $account->getId();
    }

    /**
     * Queue a rescan of $account (or get the one already queued / running).
     * An unfinished earlier rescan (Account::$rescanProgress) is continued
     * unless $restart.
     * From the mail client plugin the actor is the mailbox itself (no panel user).
     */
    public function enqueue(Account $account, string $trigger = self::TRIGGER_PANEL, bool $restart = false): EnqueueResult
    {
        $scheduled = $trigger === self::TRIGGER_SCHEDULE;
        $plugin = $trigger === self::TRIGGER_PLUGIN;
        [$actor, $actorType] = $scheduled ? ['harmonogram', AuditLog::ACTOR_CLI] : ($plugin ? [$account->getEmail(), AuditLog::ACTOR_PLUGIN] : [null, null]);
        $queued = $this->jobs->enqueue(
            BackgroundJob::TYPE_ACCOUNT_RESCAN,
            ['trigger' => $trigger] + ($restart ? ['restart' => true] : []),
            $account,
            label: ($scheduled ? 'Cotygodniowy ponowny skan: ' : 'Ponowny skan całej skrzynki: ') . ($account->getName() ?: $account->getEmail()),
            dedupeKey: self::dedupeKey($account),
            requestedBy: $actor,
            requestedByType: $actorType,
        );
        if ($queued->created) {
            $this->audit?->log('account.rescan_queued', targetType: 'account', targetId: $account->getId(), label: $account->getName(), mailbox: $account->getEmail(),
                details: ['job' => $queued->id, 'trigger' => $trigger],
                actor: $actor, actorType: $actorType);
        }
        return $queued;
    }

    /** Start of the account's weekly slot in the week of $now (may be later than $now). */
    public static function slotOfWeek(Account $account, \DateTimeImmutable $now): \DateTimeImmutable
    {
        $monday = $now->setTime(0, 0)->modify('-' . ((int)$now->format('N') - 1) . ' days');
        return $monday->modify('+' . ($account->getEffectiveRescanWeekday() - 1) . ' days')->setTime($account->getEffectiveRescanHour(), 0);
    }

    /** Most recent slot that has started (this week's or last week's). */
    public static function lastSlot(Account $account, \DateTimeImmutable $now): \DateTimeImmutable
    {
        $slot = self::slotOfWeek($account, $now);
        return $slot > $now ? $slot->modify('-7 days') : $slot;
    }

    /** Next slot after $now (shown on the account form / list). */
    public static function nextSlot(Account $account, \DateTimeImmutable $now): \DateTimeImmutable
    {
        return self::lastSlot($account, $now)->modify('+7 days');
    }

    public static function isDue(Account $account, \DateTimeImmutable $now): bool
    {
        if (!$account->getAutoRescan()) {
            return false;
        }
        if ($account->isSsh() && !$account->getAgentDeployed()) {
            return false;
        }
        $slot = self::lastSlot($account, $now);
        if ($now->getTimestamp() - $slot->getTimestamp() >= self::DUE_WINDOW_HOURS * 3600) {
            return false;
        }
        $last = $account->getLastRescanAt();
        return $last === null || $last->getTimestamp() < $slot->getTimestamp();
    }

    /** @return Account[] accounts whose weekly rescan is due at $now */
    public function dueAccounts(?\DateTimeImmutable $now = null): array
    {
        $now = $now ?? new \DateTimeImmutable();
        $accounts = $this->em->getRepository(Account::class)->findBy(['autoRescan' => true], ['id' => 'ASC']);
        return array_values(array_filter($accounts, static fn (Account $a) => self::isDue($a, $now)));
    }
}
