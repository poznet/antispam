<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\InboxService;

/**
 * Moves spam to the SPAM folder (unless the "delete" setting is on).
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
        if ($this->config->get('delete') == false && $event->isSpam()) {
            $event->getMessage()->move($this->inbox->getSpamFolder());
            $event->setDelete(true);
            $event->stopPropagation();
        }
    }
}
