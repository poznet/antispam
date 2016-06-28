<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 18.06.16
 * Time: 12:21
 */

namespace AntispamBundle\Services;

use Ddeboer\Imap\Message;
use Symfony\Component\Filesystem\Filesystem;

class MessageService
{
    /**
     * data directory
     * @var string
     */
    private $dir=__DIR__.'/../../../app/Data/checked';

    public function __construct()
    {
        $fs=new Filesystem();
        if(!$fs->exists($this->dir))
            $fs->mkdir($this->dir);
    }

    /**
     * Sets message as checked ( create fle on hdd)
     * @param Message $msg
     */
    public function setAsChecked(Message $msg){
        $id=$msg->getId();
        $nr=$msg->getNumber();
        $fs=new Filesystem();
        $name=$this->dir.'/'.$id;
        if(!$fs->exists($name))
            file_put_contents($name,$nr);
    }

    /**
     * Chceck if message exists
     * @param Message $msg
     * @return bool
     */
    public function isChecked( Message $msg){
        $id=$msg->getId();
        $fs=new Filesystem();
        $name=$this->dir.'/'.$id;
        return $fs->exists($name);
    }

    /**
     * Uncheck meessage (removes file)
     * @param Message $msg
     */
    public function unCheck(Message $msg){
        $id=$msg->getId();
        $fs=new Filesystem();
        $name=$this->dir.'/'.$id;
        if(!$fs->exists($name))
            $fs->remove($name);
    }

    /**
     * Unchecks  all messages  ( delete all messages files)
     */
    public function unCheckAll(){
        $fs=new Filesystem();
        $name=$this->dir.'/';
        $fs->remove($name);
    }


}