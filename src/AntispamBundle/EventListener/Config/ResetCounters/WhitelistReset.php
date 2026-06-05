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

class WhitelistReset
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
            $this->em->createQuery('UPDATE AntispamBundle:Whitelist w SET w.counter = 0')->execute();
        }
    }


}