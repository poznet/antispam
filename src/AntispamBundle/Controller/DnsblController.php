<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Services\DnsblService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/dnsbl')]
class DnsblController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private DnsblService $dnsbl,
    ) {
    }

    private static $presets = [
        ['name' => 'Spamhaus ZEN',     'zone' => 'zen.spamhaus.org',         'score' => 8],
        ['name' => 'Spamhaus SBL',     'zone' => 'sbl.spamhaus.org',         'score' => 8],
        ['name' => 'Spamhaus XBL',     'zone' => 'xbl.spamhaus.org',         'score' => 6],
        ['name' => 'SORBS Aggregate',  'zone' => 'dnsbl.sorbs.net',          'score' => 5],
        ['name' => 'Barracuda',        'zone' => 'b.barracudacentral.org',   'score' => 6],
        ['name' => 'SpamCop',          'zone' => 'bl.spamcop.net',           'score' => 5],
        ['name' => 'PSBL',             'zone' => 'psbl.surriel.com',         'score' => 3],
        ['name' => 'UCEPROTECT-1',     'zone' => 'dnsbl-1.uceprotect.net',   'score' => 4],
    ];

    #[Route('/', name: 'antispam_dnsbl_index')]
    #[Template('@Antispam/Dnsbl/index.html.twig')]
    public function indexAction()
    {
        $providers = $this->em->getRepository(DnsblProvider::class)->findBy([], ['name' => 'ASC']);
        return ['providers' => $providers, 'presets' => self::$presets];
    }

    #[Route('/add', name: 'antispam_dnsbl_add')]
    public function addAction(Request $request)
    {
        $name = trim((string)$request->request->get('name'));
        $zone = trim((string)$request->request->get('zone'));
        $score = (int)$request->request->get('score', 5);
        $ttl = (int)$request->request->get('ttl', 3600);

        if (!$name || !$zone) {
            $this->addFlash('danger', 'Nazwa i strefa są wymagane');
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
        if ($this->em->getRepository(DnsblProvider::class)->findOneBy(['zone' => strtolower($zone)])) {
            $this->addFlash('warning', 'Ta strefa jest już skonfigurowana');
            return $this->redirectToRoute('antispam_dnsbl_index');
        }

        $p = new DnsblProvider();
        $p->setName($name)->setZone($zone)->setScore($score)->setCacheTtl($ttl)->setEnabled(true);
        $this->em->persist($p);
        $this->em->flush();
        $this->addFlash('success', 'Dodano dostawcę DNSBL');
        return $this->redirectToRoute('antispam_dnsbl_index');
    }

    #[Route('/add-preset/{idx}', name: 'antispam_dnsbl_add_preset')]
    public function addPresetAction($idx)
    {
        $idx = (int)$idx;
        if (!isset(self::$presets[$idx])) {
            $this->addFlash('danger', 'Nie znaleziono presetu');
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
        $preset = self::$presets[$idx];
        if ($this->em->getRepository(DnsblProvider::class)->findOneBy(['zone' => $preset['zone']])) {
            $this->addFlash('warning', 'Ta strefa jest już skonfigurowana');
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
        $p = new DnsblProvider();
        $p->setName($preset['name'])->setZone($preset['zone'])->setScore($preset['score'])->setEnabled(true);
        $this->em->persist($p);
        $this->em->flush();
        $this->addFlash('success', 'Dodano preset: ' . $preset['name']);
        return $this->redirectToRoute('antispam_dnsbl_index');
    }

    #[Route('/toggle/{id}', name: 'antispam_dnsbl_toggle')]
    public function toggleAction($id)
    {
        $p = $this->em->getRepository(DnsblProvider::class)->find($id);
        if ($p) {
            $p->setEnabled(!$p->isEnabled());
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_dnsbl_index');
    }

    #[Route('/del/{id}', name: 'antispam_dnsbl_del')]
    public function delAction($id)
    {
        $p = $this->em->getRepository(DnsblProvider::class)->find($id);
        if ($p) {
            $this->em->remove($p);
            $this->em->flush();
            $this->addFlash('success', 'Usunięto dostawcę');
        }
        return $this->redirectToRoute('antispam_dnsbl_index');
    }

    /** Test a specific IP against all enabled providers. */
    #[Route('/test', name: 'antispam_dnsbl_test')]
    #[Template('@Antispam/Dnsbl/test.html.twig')]
    public function testAction(Request $request)
    {
        $ip = trim((string)$request->query->get('ip', ''));
        $results = [];
        if ($ip) {
            $results = $this->dnsbl->checkIp($ip);
        }
        return ['ip' => $ip, 'results' => $results];
    }
}
