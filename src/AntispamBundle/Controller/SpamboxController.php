<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;

/**
 * Class SpamboxController
 * @package AntispamBundle\Controller
 * @Route("/spambox")
 */
class SpamboxController extends Controller
{

    /**
     * @Template()
     * @Route("/index", name="antispam_spambox_index")
     */
    public function indexAction(){
        $list=$this->get('antispam.inbox')->getInbox($this->get('antispam.inbox')->getSpamFolderName());
        $messages=array();
        for($i=0;$i<20;$i++){
            $msg=$this->get('antispam.inbox')->getMessage($list[$i]);
            dump($msg);
            array_push($messages,array("subject"=>$msg->getSubject(),"from"=>$msg->getFrom(),"content"=>$msg->getBodyHtml(),"date"=>$msg->getDate(),"id"=>$msg->getId()));
        }
        return array('messages'=>$messages);
    }
}
