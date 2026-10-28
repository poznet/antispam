<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\RuleGlobalizer;
use AntispamBundle\Services\RuleOwnership;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/whitelist')]
class WhitelistController extends AbstractController
{
    use AuditTrait;
    use RuleMakeGlobalTrait;

    public function __construct(
        private EntityManagerInterface $em,
        private RuleOwnership $ownership,
        private ?RuleGlobalizer $globalizer = null,
    ) {
    }

    #[Route('/index', name: 'antispam_whitelist_index')]
    #[Template('@Antispam/Whitelist/index.html.twig')]
    public function indexAction(Request $request)
    {
        $all = $this->em->getRepository(Whitelist::class)->findBy([], ['id' => 'ASC']);
        $owner = (string)$request->query->get('owner', '');
        return [
            'list' => RuleOwnership::filterByOwner($all, $owner),
            'owners' => $this->ownership->labelsFor($all),
            'choices' => $this->ownership->choices(),
            'default_owner' => $this->ownership->defaultOwner(),
            'owner_filter' => $owner,
        ];
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
        if ($err = \AntispamBundle\Services\PatternMatcher::validate($host, $patternType)) {
            $this->addFlash('danger', $err);
            return $this->redirectToRoute('antispam_whitelist_index');
        }
        $owner = $this->ownership->resolve($request->request->get('owner'));
        if ($owner === null) {
            $this->addFlash('danger', 'Nieznana skrzynka - wybierz skrzynkę z listy.');
            return $this->redirectToRoute('antispam_whitelist_index');
        }
        if ($this->ownership->findDuplicate(Whitelist::class, 'host', $owner, $host)) {
            $this->addFlash('info', 'Ta reguła już istnieje dla tej skrzynki (lub dla wszystkich skrzynek).');
            return $this->redirectToRoute('antispam_whitelist_index');
        }
        $entry = new Whitelist();
        $entry->setEmail($owner);
        $entry->setHost($host);
        $entry->setPatternType($patternType);
        $this->em->persist($entry);
        $this->em->flush();
        $this->audit('rule.add', targetType: 'whitelist', targetId: $entry->getId(), label: $host, mailbox: $owner, details: ['pattern_type' => $patternType]);
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
            $this->audit('rule.delete', targetType: 'whitelist', targetId: $id, label: $entry->getHost(), mailbox: $entry->getEmail(), details: ['pattern_type' => $entry->getPatternType()]);
        }
        return $this->redirectToRoute('antispam_whitelist_index');
    }

    /** "Zmień na: Wszystkie skrzynki" for one rule (RuleMakeGlobalTrait). */
    #[Route('/global/{id}', name: 'antispam_whitelist_make_global', requirements: ['id' => '\d+'], methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function makeGlobalAction($id, Request $request)
    {
        return $this->makeGlobalOne($request, $id, 'whitelist', 'antispam_whitelist_index');
    }

    /** Checked rules (ids[]) or every rule of one mailbox (all_of) to "Wszystkie skrzynki". */
    #[Route('/global', name: 'antispam_whitelist_make_global_bulk', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function makeGlobalBulkAction(Request $request)
    {
        return $this->makeGlobalBulk($request, 'whitelist', 'antispam_whitelist_index');
    }

    /** Rule changes reshape filtering (and move mail retroactively) - POST + CSRF only. */
    private function checkToken(Request $request)
    {
        if (!$this->isCsrfTokenValid('list_rules', (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }
}
