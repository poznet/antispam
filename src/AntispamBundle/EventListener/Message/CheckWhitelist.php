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

class CheckWhitelist
{
    private $em;
    private $ms;

    public function __construct(EntityManager $entityManager,MessageService $ms)
    {
        $this->em=$entityManager;
        $this->ms=$ms;
    }

    public function check(MessageEvent $event){
        $msg=$event->getMessage();

        try {
            $host = $msg->getHeaders()->get('sender')[0]->host;
        }catch(Exception $e){
            return;
        }
        $wpis=$this->em->getRepository("AntispamBundle:Whitelist")->findOneBy(array('host'=>$host,"email"=>$event->getEmail()));
           if($wpis){
            $wpis->setCounter($wpis->getCounter()+1);
            $this->em->flush();
            $this->ms->setAsChecked($msg);
            $event->setWhitelist(true);
            $event->stopPropagation();

        }


    }

}