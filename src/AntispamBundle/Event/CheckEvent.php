<?php

namespace AntispamBundle\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * Collects configuration problems found by `antispam:check` listeners.
 */
class CheckEvent extends Event
{
    private $status = true;
    private $messages = [];

    public function getStatus()
    {
        return $this->status;
    }

    public function setStatus($status)
    {
        $this->status = $status;
    }

    public function getMessages()
    {
        return $this->messages;
    }

    public function addMessage($msg)
    {
        $this->messages[] = $msg;
    }
}
