<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 17.06.16
 * Time: 23:42
 */

namespace AntispamBundle\EventListener\Message;


use AntispamBundle\Event\MessageEvent;
use Ddeboer\Imap\Exception\Exception;
use Doctrine\ORM\EntityManager;

class CheckWhitelist
{
    private $em;

    public function __construct(EntityManager $entityManager)
    {
        $this->em=$entityManager;

    }

    public function check(MessageEvent $event){
        $msg=$event->getMessage();
        try {
            $host = $msg->getHeaders()->get('sender')[0]->host;
        }catch(Exception $e){

        }
        $wpis=$this->em->getRepository("AntispamBundle:Whitelist")->findOneBy(array('host'=>$host,"email"=>$event->getEmail()));
           if($wpis){
            $wpis->setCounter($wpis->getCounter()+1);
            $this->em->flush();
            $event->stopPropagation();

        }


    }

}