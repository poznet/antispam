<?php

namespace AntispamBundle\Controller;

use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

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

        $recentScans = array_filter($accounts, function ($a) {
            return $a->getLastScanAt() !== null;
        });
        usort($recentScans, function ($a, $b) {
            return $b->getLastScanAt() <=> $a->getLastScanAt();
        });
        $recentScans = array_slice($recentScans, 0, 5);

        $scoreRepo = $em->getRepository('AntispamBundle:SpamScoreLog');
        $stats30 = $scoreRepo->statsByDecision(new \DateTime('-30 days'));
        $daily = $scoreRepo->dailyCounts(14);
        $dailyChart = $this->groupDaily($daily);

        $dnsblCount = count($em->getRepository('AntispamBundle:DnsblProvider')->findEnabled());

        $topBlacklist = $em->createQuery(
            'SELECT b FROM AntispamBundle:Blacklist b WHERE b.counter > 0 ORDER BY b.counter DESC'
        )->setMaxResults(5)->getResult();

        $topEmailBlacklist = $em->createQuery(
            'SELECT b FROM AntispamBundle:EmailBlacklist b WHERE b.counter > 0 ORDER BY b.counter DESC'
        )->setMaxResults(5)->getResult();

        return [
            'accounts' => count($accounts),
            'whitelistCount' => $whitelistCount,
            'blacklistCount' => $blacklistCount,
            'dnsblCount' => $dnsblCount,
            'recentScans' => $recentScans,
            'stats30' => $stats30,
            'dailyChart' => $dailyChart,
            'topBlacklist' => $topBlacklist,
            'topEmailBlacklist' => $topEmailBlacklist,
        ];
    }

    private function groupDaily(array $rows)
    {
        $byDay = [];
        foreach ($rows as $r) {
            $d = $r['day'];
            if (!isset($byDay[$d])) {
                $byDay[$d] = ['day' => $d, 'ham' => 0, 'quarantine' => 0, 'spam' => 0, 'whitelisted' => 0];
            }
            $byDay[$d][$r['decision']] = (int)$r['cnt'];
        }
        ksort($byDay);
        return array_values($byDay);
    }
}
