<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\ConfigService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/whitelist')]
class WhitelistController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
    ) {
    }

    #[Route('/index', name: 'antispam_whitelist_index')]
    #[Template('@Antispam/Whitelist/index.html.twig')]
    public function indexAction()
    {
        $list = $this->em->getRepository(Whitelist::class)->findAll();
        return ['list' => $list];
    }

    #[Route('/add', name: 'antispam_whitelist_add', methods: ['POST'])]
    public function addAction(Request $request)
    {
        $this->checkToken($request);
        $host = trim((string)$request->request->get('host'));
        $patternType = $request->request->get('pattern_type', Whitelist::PATTERN_EXACT);
        if (!in_array($patternType, [Whitelist::PATTERN_EXACT, Whitelist::PATTERN_WILDCARD, Whitelist::PATTERN_REGEX], true)) {
            $patternType = Whitelist::PATTERN_EXACT;
        }
        if (!$host) {
            return $this->redirectToRoute('antispam_whitelist_index');
        }
        $existing = $this->em->getRepository(Whitelist::class)->findOneBy(['host' => $host]);
        if (!$existing) {
            $entry = new Whitelist();
            $entry->setEmail($this->config->get('email'));
            $entry->setHost($host);
            $entry->setPatternType($patternType);
            $this->em->persist($entry);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_whitelist_index');
    }

    #[Route('/del/{id}', name: 'antispam_whitelist_del', methods: ['POST'])]
    public function delAction($id, Request $request)
    {
        $this->checkToken($request);
        $entry = $this->em->getRepository(Whitelist::class)->find($id);
        if ($entry) {
            $this->em->remove($entry);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_whitelist_index');
    }

    /** Rule changes reshape filtering (and move mail retroactively) - POST + CSRF only. */
    private function checkToken(Request $request)
    {
        if (!$this->isCsrfTokenValid('list_rules', (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }
}
