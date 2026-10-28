<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\RetroactiveSpamService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/emailblacklst')]
class EmailBlacklistController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
        private RetroactiveSpamService $retroactive,
    ) {
    }

    #[Route('/index', name: 'antispam_emailblacklist_index')]
    #[Template('@Antispam/EmailBlacklist/index.html.twig')]
    public function indexAction()
    {
        $list = $this->em->getRepository(EmailBlacklist::class)->findAll();
        return ['list' => $list];
    }

    #[Route('/add', name: 'antispam_emailblacklist_add')]
    public function addAction(Request $request)
    {
        $email = trim((string)$request->request->get('email'));
        $patternType = $request->request->get('pattern_type', EmailBlacklist::PATTERN_EXACT);
        $score = (int)$request->request->get('score', 10);
        if (!in_array($patternType, [EmailBlacklist::PATTERN_EXACT, EmailBlacklist::PATTERN_WILDCARD, EmailBlacklist::PATTERN_REGEX], true)) {
            $patternType = EmailBlacklist::PATTERN_EXACT;
        }
        if (!$email) {
            return $this->redirectToRoute('antispam_emailblacklist_index');
        }
        $existing = $this->em->getRepository(EmailBlacklist::class)->findOneBy(['blacklistemail' => $email]);
        if (!$existing) {
            $entry = new EmailBlacklist();
            $entry->setEmail($this->config->get('email'));
            $entry->setBlacklistemail($email);
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
        return $this->redirectToRoute('antispam_emailblacklist_index');
    }

    #[Route('/del/{id}', name: 'antispam_emailblacklist_del')]
    public function delAction($id)
    {
        $entry = $this->em->getRepository(EmailBlacklist::class)->find($id);
        if ($entry) {
            $this->em->remove($entry);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_emailblacklist_index');
    }
}
