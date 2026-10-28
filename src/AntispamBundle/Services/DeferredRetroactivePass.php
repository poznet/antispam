<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\Jobs\EnqueueResult;
use AntispamBundle\Services\Jobs\JobQueue;

/**
 * Queues the retroactive pass of a new blacklist rule
 * (RetroactiveSpamService::applyRule - an IMAP/SSH login per mailbox plus
 * moving mail) as a background job (Jobs\Handler\RetroactiveRuleHandler), so
 * neither a panel form nor a plugin request waits for the mailboxes.
 *
 * Up to 2.0.0 this ran on kernel.terminate after the response; a job survives a
 * killed request / PHP worker, is visible in "Zadania w tle" and never holds
 * an Apache worker.
 */
class DeferredRetroactivePass
{
    public function __construct(private JobQueue $queue)
    {
    }

    /**
     * Queue the pass for a persisted rule (dedupe: one pending pass per rule).
     *
     * @param Blacklist|EmailBlacklist $rule
     */
    public function queue($rule, ?string $requestedBy = null, ?string $requestedByType = null): ?EnqueueResult
    {
        if ($rule->getId() === null) {
            return null;
        }
        $kind = $rule instanceof Blacklist ? 'blacklist' : 'email_blacklist';
        $pattern = $rule instanceof Blacklist ? $rule->getHost() : $rule->getBlacklistemail();
        return $this->queue->enqueue(
            BackgroundJob::TYPE_RULE_RETROACTIVE,
            ['rule' => $kind, 'id' => (int)$rule->getId()],
            label: 'Reguła ' . $pattern . ': poczta już w skrzynce',
            dedupeKey: 'retro:' . $kind . ':' . $rule->getId(),
            mailbox: (string)$rule->getEmail(),
            requestedBy: $requestedBy,
            requestedByType: $requestedByType,
        );
    }

    /** A rule learned from a plugin report (the mailbox account is the requester). */
    public function defer(EmailBlacklist $rule): void
    {
        $this->queue($rule, (string)$rule->getEmail(), AuditLog::ACTOR_PLUGIN);
    }
}
