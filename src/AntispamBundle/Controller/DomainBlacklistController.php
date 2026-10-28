<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\RetroactiveSpamService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/domainblacklst')]
class DomainBlacklistController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
        private RetroactiveSpamService $retroactive,
    ) {
    }

    #[Route('/index', name: 'antispam_blacklist_index')]
    #[Template('@Antispam/DomainBlacklist/index.html.twig')]
    public function indexAction()
    {
        $list = $this->em->getRepository(Blacklist::class)->findAll();
        return ['list' => $list];
    }

    #[Route('/add', name: 'antispam_blacklist_add')]
    public function addAction(Request $request)
    {
        $host = trim((string)$request->request->get('host'));
        $patternType = $request->request->get('pattern_type', Blacklist::PATTERN_EXACT);
        $score = (int)$request->request->get('score', 10);
        if (!in_array($patternType, [Blacklist::PATTERN_EXACT, Blacklist::PATTERN_WILDCARD, Blacklist::PATTERN_REGEX], true)) {
            $patternType = Blacklist::PATTERN_EXACT;
        }

        if (!$host) {
            return $this->redirectToRoute('antispam_blacklist_index');
        }

        $existing = $this->em->getRepository(Blacklist::class)->findOneBy(['host' => $host]);
        if (!$existing) {
            $entry = new Blacklist();
            $entry->setEmail($this->config->get('email'));
            $entry->setHost($host);
            $entry->setPatternType($patternType);
            $entry->setScore(max(1, $score));
            $this->em->persist($entry);
            $this->em->flush();

            // Mail from this sender that is already in INBOX goes to SPAM too.
            $summary = RetroactiveSpamService::describe($this->retroactive->applyRule($entry));
            if ($summary) {
                $this->addFlash('info', $summary);
            }
        }
        return $this->redirectToRoute('antispam_blacklist_index');
    }

    #[Route('/del/{id}', name: 'antispam_blacklist_del')]
    public function delAction($id)
    {
        $entry = $this->em->getRepository(Blacklist::class)->find($id);
        if ($entry) {
            $this->em->remove($entry);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_blacklist_index');
    }
}
