<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 17.06.16
 * Time: 23:37
 */

namespace AntispamBundle\Event;


use Ddeboer\Imap\Message;
use Symfony\Component\EventDispatcher\Event;

class MessageEvent extends Event
{

    private $message;

    public function __construct(Message $message)
    {
        $this->message = $message;
    }

    /**
     * @return mixed
     */
    public function getMessage()
    {
        return $this->message;
    }

    /**
     * @param mixed $message
     */
    public function setMessage(Message $message)
    {
        $this->message = $message;
    }



}