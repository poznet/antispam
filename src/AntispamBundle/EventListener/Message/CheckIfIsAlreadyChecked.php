<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;

/**
 * Stops the pipeline for messages already processed by a previous run -
 * except during a full rescan, which re-checks every message on purpose.
 */
class CheckIfIsAlreadyChecked
{
    private $ms;

    public function __construct(MessageService $ms)
    {
        $this->ms = $ms;
    }

    public function check(MessageEvent $event)
    {
        if ($event->isRescan()) {
            return;
        }
        if ($this->ms->isChecked($event->getMessage(), $event->getEmail())) {
            $event->setCheckedbefore(true);
            $event->stopPropagation();
        }
    }
}
