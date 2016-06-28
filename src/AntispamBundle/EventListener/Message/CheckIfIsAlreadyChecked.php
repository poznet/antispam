<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 17.06.16
 * Time: 23:42
 */

namespace AntispamBundle\EventListener\Message;


use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;
use Ddeboer\Imap\Exception\Exception;
use Doctrine\ORM\EntityManager;

class CheckIfIsAlreadyChecked
{

    private $ms;

    public function __construct(MessageService $ms)
    {
        $this->ms=$ms;
    }

    /**
     * @param MessageEvent $event
     */
    public function check(MessageEvent $event){
        $msg=$event->getMessage();
        if($this->ms->isChecked($msg)) {
            $event->setCheckedbefore(true);
            $event->stopPropagation();
        }

    }

}