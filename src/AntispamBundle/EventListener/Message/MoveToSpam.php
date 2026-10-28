<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\InboxService;

/**
 * Moves spam to the SPAM folder of the mailbox it came from, or flags it for
 * deletion when the account (or the global "delete" setting) says so. Either
 * way the message leaves INBOX on the next expunge.
 */
class MoveToSpam
{
    private $config;
    private $inbox;

    public function __construct(ConfigService $config, InboxService $inbox)
    {
        $this->config = $config;
        $this->inbox = $inbox;
    }

    public function move(MessageEvent $event)
    {
        if (!$event->isSpam()) {
            return;
        }

        $delete = $event->getDeleteSpam() ?? (bool)$this->config->get('delete');
        if ($delete) {
            $event->getMessage()->delete();
        } else {
            $event->getMessage()->move($this->inbox->getSpamFolder($event->getConnection()));
        }
        $event->setDelete(true);
        $event->stopPropagation();
    }
}
