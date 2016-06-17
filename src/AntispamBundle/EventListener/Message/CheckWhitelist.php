<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 17.06.16
 * Time: 23:42
 */

namespace AntispamBundle\EventListener\Message;


use AntispamBundle\Event\MessageEvent;
use Doctrine\ORM\EntityManager;

class CheckWhitelist
{
    private $em;

    public function __construct(EntityManager $entityManager)
    {
        $this->em=$entityManager;

    }

    public function check(MessageEvent $event){

    }

}