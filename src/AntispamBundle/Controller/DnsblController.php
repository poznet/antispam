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
    use AuditTrait;

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

    /**
     * Every action below changes the provider list: POST only, with the
     * `dnsbl` CSRF token rendered in Dnsbl/index.html.twig.
     */
    private function tokenValid(Request $request): bool
    {
        if ($this->isCsrfTokenValid('dnsbl', (string)$request->request->get('_token'))) {
            return true;
        }
        $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie.');
        return false;
    }

    #[Route('/add', name: 'antispam_dnsbl_add', methods: ['POST'])]
    public function addAction(Request $request)
    {
        if (!$this->tokenValid($request)) {
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
        $name = trim((string)$request->request->get('name'));
        $zone = trim((string)$request->request->get('zone'));
        $score = (int)$request->request->get('score', 5);
        $ttl = (int)$request->request->get('ttl', 3600);

        if (!$name || !$zone) {
            $this->addFlash('danger', 'Nazwa i strefa są wymagane');
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
        // A DNS zone (the reversed IP is prepended to it in queries).
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i', $zone)) {
            $this->addFlash('danger', 'Nieprawidłowa strefa DNS, np. zen.spamhaus.org');
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
        $name = mb_substr($name, 0, 255);
        $score = max(1, min(50, $score));
        $ttl = max(60, min(86400, $ttl));
        if ($this->em->getRepository(DnsblProvider::class)->findOneBy(['zone' => strtolower($zone)])) {
            $this->addFlash('warning', 'Ta strefa jest już skonfigurowana');
            return $this->redirectToRoute('antispam_dnsbl_index');
        }

        $p = new DnsblProvider();
        $p->setName($name)->setZone($zone)->setScore($score)->setCacheTtl($ttl)->setEnabled(true);
        $this->em->persist($p);
        $this->em->flush();
        $this->audit('dnsbl.add', targetType: 'dnsbl', targetId: $p->getId(), label: $zone, details: ['name' => $name, 'score' => $score, 'ttl' => $ttl]);
        $this->addFlash('success', 'Dodano dostawcę DNSBL');
        return $this->redirectToRoute('antispam_dnsbl_index');
    }

    #[Route('/add-preset/{idx}', name: 'antispam_dnsbl_add_preset', methods: ['POST'], requirements: ['idx' => '\d+'])]
    public function addPresetAction($idx, Request $request)
    {
        if (!$this->tokenValid($request)) {
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
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
        $this->audit('dnsbl.add', targetType: 'dnsbl', targetId: $p->getId(), label: $preset['zone'], details: ['name' => $preset['name'], 'score' => $preset['score'], 'preset' => true]);
        $this->addFlash('success', 'Dodano preset: ' . $preset['name']);
        return $this->redirectToRoute('antispam_dnsbl_index');
    }

    #[Route('/toggle/{id}', name: 'antispam_dnsbl_toggle', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function toggleAction($id, Request $request)
    {
        if (!$this->tokenValid($request)) {
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
        $p = $this->em->getRepository(DnsblProvider::class)->find($id);
        if ($p) {
            $p->setEnabled(!$p->isEnabled());
            $this->em->flush();
            $this->audit('dnsbl.toggle', targetType: 'dnsbl', targetId: $id, label: $p->getZone(), details: ['enabled' => $p->isEnabled()]);
        }
        return $this->redirectToRoute('antispam_dnsbl_index');
    }

    #[Route('/del/{id}', name: 'antispam_dnsbl_del', methods: ['POST'], requirements: ['id' => '\d+'])]
    public function delAction($id, Request $request)
    {
        if (!$this->tokenValid($request)) {
            return $this->redirectToRoute('antispam_dnsbl_index');
        }
        $p = $this->em->getRepository(DnsblProvider::class)->find($id);
        if ($p) {
            $this->em->remove($p);
            $this->em->flush();
            $this->audit('dnsbl.delete', targetType: 'dnsbl', targetId: $id, label: $p->getZone(), details: ['name' => $p->getName()]);
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
