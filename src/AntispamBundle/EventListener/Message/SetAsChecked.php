<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;

/**
 * Last pipeline step: remembers the message so the next run skips it.
 */
class SetAsChecked
{
    private $ms;

    public function __construct(MessageService $ms)
    {
        $this->ms = $ms;
    }

    public function set(MessageEvent $event)
    {
        $this->ms->setAsChecked($event->getMessage(), $event->getEmail());
    }
}
