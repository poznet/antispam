<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Event\ConfigEvent;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;


/**
 * Class ConfigurationController
 * @package AntispamBundle\Controller
 * @Route("/config")
 */
class ConfigurationController extends Controller
{

    /**
     * @Route("/email/", name="antispam_account_config")
     * @Template
     */
    public function emailConfigAction(Request $request)
    {

        if($request->getMethod()=='POST'){
            $this->get('configuration')->set('email',$request->get('config')['email']);
            $this->get('configuration')->set('password',$request->get('config')['password']);
            $this->get('configuration')->set('login',$request->get('config')['login']);
            $this->get('configuration')->set('imap',$request->get('config')['imap']);
            if(!array_key_exists('delete',$request->get('config'))){
                $this->get('configuration')->set('delete', false);
            }else{
                $this->get('configuration')->set('delete', true);
            }

        }
        $config=array();
        $config['email']=$this->get('configuration')->get('email');
        $config['password']=$this->get('configuration')->get('password');
        $config['login']=$this->get('configuration')->get('login');
        $config['imap']=$this->get('configuration')->get('imap');
        $config['delete']=$this->get('configuration')->get('delete');



        return array('config'=>$config);
    }

    /**
     * @return array
     * @Template
     * @Route("/spam/", name="antispam_spam_config")
     */
    public function spamConfigAction(Request $request){
        if($request->getMethod()=='POST'){
            if(!array_key_exists('delete',$request->get('config'))){
                $this->get('configuration')->set('delete', false);
            }else{
                $this->get('configuration')->set('delete', true);
            }
        }
        $config=array();
        $config['delete']=$this->get('configuration')->get('delete');
        return array('config'=>$config);
    }

    /**
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     * @Route("/uncheck-all/", name="antispam_spam_unchekall")
     */
    public function uncheckAllAction(){
        $this->get('antispam.message')->unCheckAll();
        return $this->redirectToRoute('antispam_spam_config');
    }

    /**
     * @Route("/reset/countes/", name="antispam_spam_resetcounters")
     */
    public function resetCountersAction(){
        $dispatcher = $this->get('event_dispatcher');
        $event=new ConfigEvent('resetcounters');
        $dispatcher->dispatch('antispam.config.event', $event);
        return $this->redirectToRoute('antispam_spam_config');
    }
}
