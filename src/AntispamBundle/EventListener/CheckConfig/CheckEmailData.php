<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 16.06.16
 * Time: 22:41
 */

namespace AntispamBundle\EventListener\CheckConfig;


use AntispamBundle\Event\CheckEvent;
use Ddeboer\Imap\Exception\Exception;
use Poznet\ConfigBundle\Service\ConfigService;
use Ddeboer\Imap\Server;

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

    /**
     * Checking connection to server
     * @param CheckEvent $event
     */
    public function tryToConnect(CheckEvent $event){
        if($event->getStatus()===true){
            $server = new Server($this->config->get('imap'));
            $server = new Server(
                $this->config->get('imap'),
                143,
                '/novalidate-cert/notls'

            );
            try {
                $server->authenticate($this->config->get('login'), $this->config->get('password'));
            } catch (Exception $e){
                $event->setStatus(false);
                $event->addMessage("Connection :  ".$e->getMessage());
                
            }

        }

    }

}