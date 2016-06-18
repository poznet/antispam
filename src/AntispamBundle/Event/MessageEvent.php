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
    private $delete;
    private $whitelist;
    private $blacklist;
    private $spamscore;
    private $checkedbefore;


    public function __construct(Message $message,$email=null)
    {
        $this->message = $message;
        $this->email=$email;
        $this->delete=false;
        $this->spamscore=0;
        $this->whitelist=false;
        $this->blacklist=false;
        $this->checkedbefore=false;
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

    /**
     * @return boolean
     */
    public function isDelete()
    {
        return $this->delete;
    }

    /**
     * @param boolean $delete
     */
    public function setDelete($delete)
    {
        $this->delete = $delete;
    }

    /**
     * @return boolean
     */
    public function isWhitelist()
    {
        return $this->whitelist;
    }

    /**
     * @param boolean $whitelist
     */
    public function setWhitelist($whitelist)
    {
        $this->whitelist = $whitelist;
    }

    /**
     * @return boolean
     */
    public function isBlacklist()
    {
        return $this->blacklist;
    }

    /**
     * @param boolean $blacklist
     */
    public function setBlacklist($blacklist)
    {
        $this->blacklist = $blacklist;
    }

    /**
     * @return int
     */
    public function getSpamscore()
    {
        return $this->spamscore;
    }

    /**
     * @param int $spamscore
     */
    public function setSpamscore($spamscore)
    {
        $this->spamscore = $spamscore;
    }

    /**
     * @return boolean
     */
    public function isCheckedbefore()
    {
        return $this->checkedbefore;
    }

    /**
     * @param boolean $checkedbefore
     */
    public function setCheckedbefore($checkedbefore)
    {
        $this->checkedbefore = $checkedbefore;
    }



}