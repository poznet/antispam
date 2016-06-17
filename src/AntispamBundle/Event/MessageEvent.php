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
    private $email;

    public function __construct(Message $message,$email=null)
    {
        $this->message = $message;
        $this->email=$email;
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

    /**
    * @return null
    */
    public function getEmail()
    {
        return $this->email;
    }/**
     * @param null $email
     */
    public function setEmail($email)
    {
        $this->email = $email;
    }


}