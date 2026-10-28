<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Services\RetroactiveSpamService;
use AntispamBundle\Services\RuleOwnership;
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
        private RuleOwnership $ownership,
        private RetroactiveSpamService $retroactive,
    ) {
    }

    #[Route('/index', name: 'antispam_blacklist_index')]
    #[Template('@Antispam/DomainBlacklist/index.html.twig')]
    public function indexAction(Request $request)
    {
        $all = $this->em->getRepository(Blacklist::class)->findBy([], ['id' => 'ASC']);
        $owner = (string)$request->query->get('owner', '');
        return [
            'list' => RuleOwnership::filterByOwner($all, $owner),
            'owners' => $this->ownership->labelsFor($all),
            'choices' => $this->ownership->choices(),
            'default_owner' => $this->ownership->defaultOwner(),
            'owner_filter' => $owner,
        ];
    }

    #[Route('/add', name: 'antispam_blacklist_add', methods: ['POST'])]
    public function addAction(Request $request)
    {
        $this->checkToken($request);
        $host = trim((string)$request->request->get('host'));
        $patternType = $request->request->get('pattern_type', Blacklist::PATTERN_EXACT);
        $score = (int)$request->request->get('score', 10);
        if (!in_array($patternType, [Blacklist::PATTERN_EXACT, Blacklist::PATTERN_WILDCARD, Blacklist::PATTERN_REGEX], true)) {
            $patternType = Blacklist::PATTERN_EXACT;
        }

        if (!$host) {
            return $this->redirectToRoute('antispam_blacklist_index');
        }
        $owner = $this->ownership->resolve($request->request->get('owner'));
        if ($owner === null) {
            $this->addFlash('danger', 'Nieznana skrzynka - wybierz skrzynkę z listy.');
            return $this->redirectToRoute('antispam_blacklist_index');
        }
        if ($this->ownership->findDuplicate(Blacklist::class, 'host', $owner, $host)) {
            $this->addFlash('info', 'Ta reguła już istnieje dla tej skrzynki (lub dla wszystkich skrzynek).');
            return $this->redirectToRoute('antispam_blacklist_index');
        }

        $entry = new Blacklist();
        $entry->setEmail($owner);
        $entry->setHost($host);
        $entry->setPatternType($patternType);
        $entry->setScore(max(1, $score));
        $this->em->persist($entry);
        $this->em->flush();

        // Mail from this domain that is already in INBOX goes to SPAM too.
        $summary = RetroactiveSpamService::describe($this->retroactive->applyRule($entry));
        if ($summary) {
            $this->addFlash('info', $summary);
        }
        return $this->redirectToRoute('antispam_blacklist_index');
    }

    #[Route('/del/{id}', name: 'antispam_blacklist_del', methods: ['POST'])]
    public function delAction($id, Request $request)
    {
        $this->checkToken($request);
        $entry = $this->em->getRepository(Blacklist::class)->find($id);
        if ($entry) {
            $this->em->remove($entry);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_blacklist_index');
    }

    /** Rule changes reshape filtering (and move mail retroactively) - POST + CSRF only. */
    private function checkToken(Request $request)
    {
        if (!$this->isCsrfTokenValid('list_rules', (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }
}
