<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 16.06.16
 * Time: 22:34
 */

namespace AntispamBundle\Event;


use Symfony\Component\EventDispatcher\Event;

class CheckEvent extends Event
{
    private $status=true;
    private $messages=array();

    /**
     * @return null
     */
    public function getStatus()
    {
        return $this->status;
    }

    /**
     * @param null $status
     */
    public function setStatus($status)
    {
        $this->status = $status;
    }

    /**
     * @return array
     */
    public function getMessages()
    {
        return $this->messages;
    }

    /**
     * @param array $messages
     */
    public function setMessages($messages)
    {
        $this->messages = $messages;
    }

    /**
     * @param $msg
     */
    public function addMessage($msg){
        array_push($this->messages,$msg);
    }


}