<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;

/**
 * Stops the pipeline for messages already processed by a previous run.
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
        if ($this->ms->isChecked($event->getMessage())) {
            $event->setCheckedbefore(true);
            $event->stopPropagation();
        }
    }
}
