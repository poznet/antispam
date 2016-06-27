<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;

/**
 * Class AjaxController
 * @package AntispamBundle\Controller
 * @Route("/ajax")
 */
class AjaxController extends Controller
{

    /**
     * @param $id
     * @Route("/getmsg/{id}")
     */
    public function getMsgAction($id){
        $mailbox=$this->get('antispam.inbox')->getInbox($this->get('antispam.inbox')->getSpamFolderName());

        $search = new SearchExpression();
        $search->addCondition(new Id($id));

        $msg = $mailbox->getMessages($search);
        dump($msg);
        return array('msg'=>$msg);
    }
}
