<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Ddeboer\Imap\SearchExpression;



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
        $mailbox=$this->get('antispam.inbox')->getMessage();

        return array('msg'=>$msg);
    }
}
