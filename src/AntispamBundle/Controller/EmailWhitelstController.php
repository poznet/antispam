<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;

/**
 * Class EmailWhitelstController
 * @package AntispamBundle\Controller
 * @Route("/emailwhitelist")
 */
class EmailWhitelstController extends Controller
{
    /**
     *  @Route("/index", name="antispam_emailwhitelist_index")
     *  @Template()
     */
    public function indexAction(){
        return array();
    }
}
