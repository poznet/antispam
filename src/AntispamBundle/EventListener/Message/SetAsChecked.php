<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 19.06.16
 * Time: 00:20
 */

namespace AntispamBundle\EventListener\Message;


use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\InboxService;
use Poznet\ConfigBundle\Service\ConfigService;
use AntispamBundle\Services\MessageService;

class SetAsChecked
{
    private $ms;


    public function __construct(MessageService $ms){
        $this->ms=$ms;

    }


    public function set(MessageEvent $event){
         $msg=$event->getMessage();
         $this->ms->setAsChecked($msg->getId());
    }

}