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

        $idek=$this->get('antispam.message')->getId(trim($id));
        $list=$this->get('antispam.inbox')->getInbox($this->get('antispam.inbox')->getSpamFolderName());
        $msg=$this->get('antispam.inbox')->getMessage($id);


            dump($msg);
        return array();
    }
}
