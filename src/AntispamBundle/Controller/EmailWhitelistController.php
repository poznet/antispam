<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Services\RuleOwnership;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/emailwhitelist')]
class EmailWhitelistController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private RuleOwnership $ownership,
    ) {
    }

    #[Route('/index', name: 'antispam_emailwhitelist_index')]
    #[Template('@Antispam/EmailWhitelist/index.html.twig')]
    public function indexAction(Request $request)
    {
        $all = $this->em->getRepository(EmailWhitelist::class)->findBy([], ['id' => 'ASC']);
        $owner = (string)$request->query->get('owner', '');
        return [
            'list' => RuleOwnership::filterByOwner($all, $owner),
            'owners' => $this->ownership->labelsFor($all),
            'choices' => $this->ownership->choices(),
            'default_owner' => $this->ownership->defaultOwner(),
            'owner_filter' => $owner,
        ];
    }

    #[Route('/add', name: 'antispam_emailwhitelist_add', methods: ['POST'])]
    public function addAction(Request $request)
    {
        $this->checkToken($request);
        $email = trim((string)$request->request->get('email'));
        $patternType = $request->request->get('pattern_type', EmailWhitelist::PATTERN_EXACT);
        if (!in_array($patternType, [EmailWhitelist::PATTERN_EXACT, EmailWhitelist::PATTERN_WILDCARD, EmailWhitelist::PATTERN_REGEX], true)) {
            $patternType = EmailWhitelist::PATTERN_EXACT;
        }
        if (!$email) {
            return $this->redirectToRoute('antispam_emailwhitelist_index');
        }
        $owner = $this->ownership->resolve($request->request->get('owner'));
        if ($owner === null) {
            $this->addFlash('danger', 'Nieznana skrzynka - wybierz skrzynkę z listy.');
            return $this->redirectToRoute('antispam_emailwhitelist_index');
        }
        if ($this->ownership->findDuplicate(EmailWhitelist::class, 'whitelistemail', $owner, $email)) {
            $this->addFlash('info', 'Ta reguła już istnieje dla tej skrzynki (lub dla wszystkich skrzynek).');
            return $this->redirectToRoute('antispam_emailwhitelist_index');
        }
        $entry = new EmailWhitelist();
        $entry->setEmail($owner);
        $entry->setWhitelistemail($email);
        $entry->setPatternType($patternType);
        $this->em->persist($entry);
        $this->em->flush();
        return $this->redirectToRoute('antispam_emailwhitelist_index');
    }

    #[Route('/del/{id}', name: 'antispam_emailwhitelist_del', methods: ['POST'])]
    public function delAction($id, Request $request)
    {
        $this->checkToken($request);
        $entry = $this->em->getRepository(EmailWhitelist::class)->find($id);
        if ($entry) {
            $this->em->remove($entry);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_emailwhitelist_index');
    }

    /** Rule changes reshape filtering (and move mail retroactively) - POST + CSRF only. */
    private function checkToken(Request $request)
    {
        if (!$this->isCsrfTokenValid('list_rules', (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }
}
