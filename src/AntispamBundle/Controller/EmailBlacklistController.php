<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;

/**
 * Class EmailBlacklistController
 * @package AntispamBundle\Controller
 * @Route("/emailblacklst")
 */
class EmailBlacklistController extends Controller
{
    /**
     * @Route("/index", name="antispam_emailblacklist_index")
     * @Template
     */
    public function indexAction(){
        $em = $this->getDoctrine()->getManager();
        $list=$em->getRepository("AntispamBundle:EmailBlacklist")->findAll();
        return array('list'=>$list);
    }
}
