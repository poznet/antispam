<?php

namespace AntispamBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

/**
 * In-app documentation for end-users and admins: how the agent works, how to
 * connect accounts, how rules are matched, DNSBL, scoring pipeline, CLI.
 *
 * @Route("/help")
 */
class HelpController extends Controller
{
    /**
     * @Route("/", name="antispam_help_index")
     * @Template()
     */
    public function indexAction()
    {
        return [];
    }
}
