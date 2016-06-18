<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;

class DefaultController extends Controller
{

    /**
     * @Route("/", name="antispam_index")
     * @Template
     */
    public function indexAction(){
        return array();
    }

    
    /**
     * @Route("/config/", name="antispam_config")
     * @Template
     */
    public function configAction(Request $request)
    {

        if($request->getMethod()=='POST'){
            $this->get('configuration')->set('email',$request->get('config')['email']);
            $this->get('configuration')->set('password',$request->get('config')['password']);
            $this->get('configuration')->set('login',$request->get('config')['login']);
            $this->get('configuration')->set('imap',$request->get('config')['imap']);

        }
        $config=array();
        $config['email']=$this->get('configuration')->get('email');
        $config['password']=$this->get('configuration')->get('password');
        $config['login']=$this->get('configuration')->get('login');
        $config['imap']=$this->get('configuration')->get('imap');


        return array('config'=>$config);
    }
}
