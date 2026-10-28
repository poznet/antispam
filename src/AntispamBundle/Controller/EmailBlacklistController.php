<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\RuleGlobalizer;
use AntispamBundle\Services\RuleOwnership;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/emailblacklst')]
class EmailBlacklistController extends AbstractController
{
    use AuditTrait;
    use RuleMakeGlobalTrait;
    use JobQueueTrait;

    public function __construct(
        private EntityManagerInterface $em,
        private RuleOwnership $ownership,
        private DeferredRetroactivePass $retroactive,
        private ?RuleGlobalizer $globalizer = null,
    ) {
    }

    #[Route('/index', name: 'antispam_emailblacklist_index')]
    #[Template('@Antispam/EmailBlacklist/index.html.twig')]
    public function indexAction(Request $request)
    {
        $all = $this->em->getRepository(EmailBlacklist::class)->findBy([], ['id' => 'ASC']);
        $owner = (string)$request->query->get('owner', '');
        return [
            'list' => RuleOwnership::filterByOwner($all, $owner),
            'owners' => $this->ownership->labelsFor($all),
            'choices' => $this->ownership->choices(),
            'default_owner' => $this->ownership->defaultOwner(),
            'owner_filter' => $owner,
        ];
    }

    #[Route('/add', name: 'antispam_emailblacklist_add', methods: ['POST'])]
    public function addAction(Request $request)
    {
        $this->checkToken($request);
        $email = trim((string)$request->request->get('email'));
        $patternType = $request->request->get('pattern_type', EmailBlacklist::PATTERN_EXACT);
        $score = (int)$request->request->get('score', 10);
        if (!in_array($patternType, [EmailBlacklist::PATTERN_EXACT, EmailBlacklist::PATTERN_WILDCARD, EmailBlacklist::PATTERN_REGEX], true)) {
            $patternType = EmailBlacklist::PATTERN_EXACT;
        }
        if (!$email) {
            return $this->redirectToRoute('antispam_emailblacklist_index');
        }
        if ($err = \AntispamBundle\Services\PatternMatcher::validate($email, $patternType)) {
            $this->addFlash('danger', $err);
            return $this->redirectToRoute('antispam_emailblacklist_index');
        }
        $owner = $this->ownership->resolve($request->request->get('owner'));
        if ($owner === null) {
            $this->addFlash('danger', 'Nieznana skrzynka - wybierz skrzynkę z listy.');
            return $this->redirectToRoute('antispam_emailblacklist_index');
        }
        if ($this->ownership->findDuplicate(EmailBlacklist::class, 'blacklistemail', $owner, $email)) {
            $this->addFlash('info', 'Ta reguła już istnieje dla tej skrzynki (lub dla wszystkich skrzynek).');
            return $this->redirectToRoute('antispam_emailblacklist_index');
        }

        $entry = new EmailBlacklist();
        $entry->setEmail($owner);
        $entry->setBlacklistemail($email);
        $entry->setPatternType($patternType);
        $entry->setScore(max(1, $score));
        $this->em->persist($entry);
        $this->em->flush();
        $this->audit('rule.add', targetType: 'email_blacklist', targetId: $entry->getId(), label: $email, mailbox: $owner, details: ['pattern_type' => $patternType, 'score' => $entry->getScore()]);

        // Mail from this sender that is already in INBOX goes to SPAM too.
        // Checked in the background (an IMAP/SSH login per mailbox), docs/jobs.md.
        $this->flashRetroactive($this->retroactive->queue($entry));
        return $this->redirectToRoute('antispam_emailblacklist_index');
    }

    #[Route('/del/{id}', name: 'antispam_emailblacklist_del', methods: ['POST'])]
    public function delAction($id, Request $request)
    {
        $this->checkToken($request);
        $entry = $this->em->getRepository(EmailBlacklist::class)->find($id);
        if ($entry) {
            $this->em->remove($entry);
            $this->em->flush();
            $this->audit('rule.delete', targetType: 'email_blacklist', targetId: $id, label: $entry->getBlacklistemail(), mailbox: $entry->getEmail(), details: ['pattern_type' => $entry->getPatternType()]);
        }
        return $this->redirectToRoute('antispam_emailblacklist_index');
    }

    /** "Zmień na: Wszystkie skrzynki" for one rule (RuleMakeGlobalTrait). */
    #[Route('/global/{id}', name: 'antispam_emailblacklist_make_global', requirements: ['id' => '\d+'], methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function makeGlobalAction($id, Request $request)
    {
        return $this->makeGlobalOne($request, $id, 'email_blacklist', 'antispam_emailblacklist_index');
    }

    /** Checked rules (ids[]) or every rule of one mailbox (all_of) to "Wszystkie skrzynki". */
    #[Route('/global', name: 'antispam_emailblacklist_make_global_bulk', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function makeGlobalBulkAction(Request $request)
    {
        return $this->makeGlobalBulk($request, 'email_blacklist', 'antispam_emailblacklist_index');
    }

    /** Rule changes reshape filtering (and move mail retroactively) - POST + CSRF only. */
    private function checkToken(Request $request)
    {
        if (!$this->isCsrfTokenValid('list_rules', (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }
}
