<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\Whitelist;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Attribute\Route;

class DefaultController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
    ) {
    }

    #[Route('/panel', name: 'antispam_index')]
    #[Template('@Antispam/Default/index.html.twig')]
    public function indexAction()
    {
        $accounts = $this->em->getRepository(Account::class)->findAll();
        $whitelistCount = count($this->em->getRepository(Whitelist::class)->findAll())
            + count($this->em->getRepository(EmailWhitelist::class)->findAll());
        $blacklistCount = count($this->em->getRepository(Blacklist::class)->findAll())
            + count($this->em->getRepository(EmailBlacklist::class)->findAll());

        $recentScans = array_filter($accounts, function ($a) {
            return $a->getLastScanAt() !== null;
        });
        usort($recentScans, function ($a, $b) {
            return $b->getLastScanAt() <=> $a->getLastScanAt();
        });
        $recentScans = array_slice($recentScans, 0, 5);

        $scoreRepo = $this->em->getRepository(SpamScoreLog::class);
        $stats30 = $scoreRepo->statsByDecision(new \DateTime('-30 days'));
        $daily = $scoreRepo->dailyCounts(14);
        $dailyChart = $this->groupDaily($daily);

        $dnsblCount = count($this->em->getRepository(DnsblProvider::class)->findEnabled());

        $topBlacklist = $this->em->createQuery(
            'SELECT b FROM AntispamBundle\Entity\Blacklist b WHERE b.counter > 0 ORDER BY b.counter DESC'
        )->setMaxResults(5)->getResult();

        $topEmailBlacklist = $this->em->createQuery(
            'SELECT b FROM AntispamBundle\Entity\EmailBlacklist b WHERE b.counter > 0 ORDER BY b.counter DESC'
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
