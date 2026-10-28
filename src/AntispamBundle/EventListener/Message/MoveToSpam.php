<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\ScoringService;

/**
 * Moves spam to the SPAM folder of the mailbox it came from, or flags it for
 * deletion when the account (or the global "delete" setting) says so. Either
 * way the message leaves INBOX on the next expunge.
 */
class MoveToSpam
{
    private $config;
    private $inbox;
    private $scoring;

    public function __construct(ConfigService $config, InboxService $inbox, ScoringService $scoring)
    {
        $this->config = $config;
        $this->inbox = $inbox;
        $this->scoring = $scoring;
    }

    public function move(MessageEvent $event)
    {
        if (!$event->isSpam()) {
            return;
        }

        $delete = $event->getDeleteSpam() ?? (bool)$this->config->get('delete');
        try {
            if ($delete) {
                $event->getMessage()->delete();
            } else {
                $event->getMessage()->move($this->inbox->getSpamFolder($event->getConnection()));
            }
        } catch (\Throwable $e) {
            $this->scoring->recordOutcome($event->getScoreLog(), SpamScoreLog::OUTCOME_MOVE_FAILED);
            throw $e;
        }
        $this->scoring->recordOutcome($event->getScoreLog(), $delete ? SpamScoreLog::OUTCOME_DELETED : SpamScoreLog::OUTCOME_SPAM_FOLDER);
        $event->setDelete(true);
        $event->stopPropagation();
    }
}
