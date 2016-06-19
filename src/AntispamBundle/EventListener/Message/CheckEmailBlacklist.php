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

class CheckEmailBlacklist
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
            $email = $msg->getHeaders()->get('sender')[0]->mailbox.'@'.$msg->getHeaders()->get('sender')[0]->host;
        }catch(Exception $e){

        }
        $wpis=$this->em->getRepository("AntispamBundle:EmailBlacklist")->findOneBy(array('blacklistemail'=>$email,"email"=>$event->getEmail()));
           if($wpis){
            $wpis->setCounter($wpis->getCounter()+1);
            $this->em->flush();
            $this->ms->setAsChecked($msg->getId());
            $event->setBlacklist(true);
            $event->setSpam(true);
//            $event->stopPropagation();
        }


    }

}