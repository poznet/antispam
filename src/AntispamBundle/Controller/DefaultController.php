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

        // Compute total spam caught from scan logs (last 30 days)
        $spamCount = 0;
        $dailyStats = [];
        try {
            $since = new \DateTime('-30 days');
            $logs = $em->getRepository('AntispamBundle:ScanLog')->createQueryBuilder('l')
                ->where('l.scannedAt >= :since')
                ->andWhere('l.success = true')
                ->setParameter('since', $since)
                ->orderBy('l.scannedAt', 'ASC')
                ->getQuery()
                ->getResult();

            foreach ($logs as $log) {
                $spamCount += $log->getMovedToSpam();
                $day = $log->getScannedAt()->format('Y-m-d');
                if (!isset($dailyStats[$day])) {
                    $dailyStats[$day] = ['total' => 0, 'spam' => 0, 'whitelisted' => 0];
                }
                $dailyStats[$day]['total'] += $log->getTotalMessages();
                $dailyStats[$day]['spam'] += $log->getMovedToSpam();
                $dailyStats[$day]['whitelisted'] += $log->getWhitelisted();
            }

            // Top blacklisted domains
            $topDomains = $em->createQuery(
                'SELECT b.host, SUM(b.counter) as cnt FROM AntispamBundle:Blacklist b GROUP BY b.host ORDER BY cnt DESC'
            )->setMaxResults(10)->getResult();
        } catch (\Exception $e) {
            $topDomains = [];
        }

        // Accounts needing sync
        $needsSyncCount = 0;
        foreach ($accounts as $a) {
            if ($a->isSsh() && $a->getNeedsSync()) {
                $needsSyncCount++;
            }
        }

        return [
            'accounts' => count($accounts),
            'whitelistCount' => $whitelistCount,
            'blacklistCount' => $blacklistCount,
            'spamCount' => $spamCount,
            'needsSyncCount' => $needsSyncCount,
            'recentScans' => $recentScans,
            'dailyStats' => $dailyStats,
            'topDomains' => $topDomains ?? [],
        ];
    }
}
