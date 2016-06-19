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

class MoveToSpam
{
    private $config;
    private $inbox;

    public function __construct(ConfigService $config,InboxService $inbox){
        $this->config=$config;
        $this->inbox=$inbox;
    }


    public function move(MessageEvent $event){
        if($this->config->get('delete')==false){
            if ($event->isSpam()) {

                $spam=$this->inbox->getSpamFolder();
                $event->getMessage()->move($spam);
                $event->setDelete(true);
                $event->stopPropagation();
            }


        }
    }

}