<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 16.06.16
 * Time: 22:41
 */

namespace AntispamBundle\EventListener\CheckConfig;


use AntispamBundle\Event\CheckEvent;
use Poznet\ConfigBundle\Service\ConfigService;

class CheckEmailData
{
    private $config;

    public function __construct(ConfigService $config)
    {
        $this->config=$config;
    }

    public function checkEmail(CheckEvent $event){
        $email=$this->config->get('email');
        if(strlen($email)<3){
            $event->setStatus(false);
            $event->addMessage("Configuration : Wrong Email");
        }
    }

    public function checkLogin(CheckEvent $event){
        $var=$this->config->get('login');
        if(strlen(trim($var))<2){
            $event->setStatus(false);
            $event->addMessage("Configuration : Empty Login");
        }
    }

    public function checkPass(CheckEvent $event){
        $var=$this->config->get('password');
        if(strlen(trim($var))<2){
            $event->setStatus(false);
            $event->addMessage("Configuration : Empty Password");
        }
    }

    public function checkImap(CheckEvent $event){
        $var=$this->config->get('imap');
        if(strlen(trim($var))<3){
            $event->setStatus(false);
            $event->addMessage("Configuration : Empty Imap Server");
        }
    }

}