<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;

class DefaultController extends Controller
{
    /**
     * @Route("/", name="antispam_index")
     * @Template
     */
    public function indexAction()
    {
        $em = $this->getDoctrine()->getManager();

        $accounts = $em->getRepository('AntispamBundle:Account')->findAll();
        $whitelistCount = count($em->getRepository('AntispamBundle:Whitelist')->findAll())
            + count($em->getRepository('AntispamBundle:EmailWhitelist')->findAll());
        $blacklistCount = count($em->getRepository('AntispamBundle:Blacklist')->findAll())
            + count($em->getRepository('AntispamBundle:EmailBlacklist')->findAll());

        $recentScans = array_filter($accounts, function($a) {
            return $a->getLastScanAt() !== null;
        });
        usort($recentScans, function($a, $b) {
            return $b->getLastScanAt() <=> $a->getLastScanAt();
        });
        $recentScans = array_slice($recentScans, 0, 5);

        return [
            'accounts' => count($accounts),
            'whitelistCount' => $whitelistCount,
            'blacklistCount' => $blacklistCount,
            'recentScans' => $recentScans,
        ];
    }
}
