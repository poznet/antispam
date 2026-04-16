<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\InboxService;

/**
 * Final scoring step: turns the accumulated score into ham/quarantine/spam
 * and handles moving quarantined messages to a separate IMAP folder.
 *
 * Spam-marking is already done by CheckBlacklist / ScoringService::decide;
 * this listener only needs to physically handle QUARANTINE.
 */
class ApplyScoreDecision
{
    private $scoring;
    private $inbox;

    public function __construct(ScoringService $scoring, InboxService $inbox)
    {
        $this->scoring = $scoring;
        $this->inbox = $inbox;
    }

    public function decide(MessageEvent $event)
    {
        if ($event->isCheckedbefore()) {
            return;
        }

        $msg = $event->getMessage();
        $sender = '';
        $subject = '';
        try {
            if ($msg->getFrom()) { $sender = $msg->getFrom()->getAddress(); }
        } catch (\Throwable $e) {}
        try {
            $subject = (string)$msg->getSubject();
        } catch (\Throwable $e) {}

        $reasons = CheckHeaders::getReasons($event);
        $decision = $this->scoring->decide($event, $reasons, $sender, $subject);

        if ($decision === \AntispamBundle\Entity\SpamScoreLog::DECISION_QUARANTINE && !$event->isSpam()) {
            try {
                $quarantine = $this->inbox->getQuarantineFolder();
                $event->getMessage()->move($quarantine);
                $event->setDelete(true);
                $event->stopPropagation();
            } catch (\Throwable $e) {
                // fall through - quarantine failed, leave message in inbox
            }
        }
    }
}
