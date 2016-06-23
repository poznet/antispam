<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 23.06.16
 * Time: 22:29
 */

namespace AntispamBundle\EventListener\Config\ResetCounters;

use AntispamBundle\Event\ConfigEvent;
use Doctrine\ORM\EntityManager;

class BlacklistReset
{
    private $em;

    public function __construct(EntityManager $em)
    {
        $this->em=$em;
    }

    /**
     * @param ConfigEvent $event
     */
    public function reset(ConfigEvent $event){
        if($event->getJob()=='resetcounters'){
        $lista=$this->em->getRepository("AntispamBundle:Blacklist")->findAll();
            $i=0;
            foreach ($lista as $l){
                $l->setCounter(0);
                if($i==200){
                    $this->em->flush();
                    $i=0;
                }
            }
            $this->em->flush();

        }
    }


}