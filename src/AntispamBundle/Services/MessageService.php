<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 18.06.16
 * Time: 12:21
 */

namespace AntispamBundle\Services;

use Symfony\Component\Filesystem\Filesystem;

class MessageService
{
    private $dir=__DIR__.'/../../../app/Data/checked';

    public function __construct()
    {
        $fs=new Filesystem();
        if(!$fs->exists($this->dir))
            $fs->mkdir($this->dir);
    }


    public function setAsChecked($id){
        $fs=new Filesystem();
        $name=$this->dir.'/'.$id;
        if(!$fs->exists($name))
            file_put_contents($name,".");
    }

    public function isChecked($id){
        $fs=new Filesystem();
        $name=$this->dir.'/'.$id;
        return $fs->exists($name);
    }

    public function unCheck($id){
        $fs=new Filesystem();
        $name=$this->dir.'/'.$id;
        if(!$fs->exists($name))
            $fs->remove($name);
    }

}