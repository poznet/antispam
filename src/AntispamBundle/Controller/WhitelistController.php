<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;

/**
 *
 * Class WhitelistController
 * @package AntispamBundle\Controller
 * @Route("/whitelist")
 */
class WhitelistController extends Controller
{

    /**
     * @Route("/index", name="antispam_whitelist_index")
     * @Template
     */
    public function indexAction(){
        return array();
    }

}
