<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 23.06.16
 * Time: 22:26
 */

namespace AntispamBundle\Event;


use Symfony\Component\EventDispatcher\Event;

class ConfigEvent extends Event
{
    private $job='';


    public function __construct($job)
    {
        $this->job=$job;
    }

    /**
     * @return string
     */
    public function getJob()
    {
        return $this->job;
    }

    /**
     * @param string $job
     */
    public function setJob($job)
    {
        $this->job = $job;
    }



}