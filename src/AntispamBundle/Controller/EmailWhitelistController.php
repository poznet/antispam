<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Services\ConfigService;
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
        private ConfigService $config,
    ) {
    }

    #[Route('/index', name: 'antispam_emailwhitelist_index')]
    #[Template('@Antispam/EmailWhitelist/index.html.twig')]
    public function indexAction()
    {
        $list = $this->em->getRepository(EmailWhitelist::class)->findAll();
        return ['list' => $list];
    }

    #[Route('/add', name: 'antispam_emailwhitelist_add')]
    public function addAction(Request $request)
    {
        $email = trim((string)$request->request->get('email'));
        $patternType = $request->request->get('pattern_type', EmailWhitelist::PATTERN_EXACT);
        if (!in_array($patternType, [EmailWhitelist::PATTERN_EXACT, EmailWhitelist::PATTERN_WILDCARD, EmailWhitelist::PATTERN_REGEX], true)) {
            $patternType = EmailWhitelist::PATTERN_EXACT;
        }
        if (!$email) {
            return $this->redirectToRoute('antispam_emailwhitelist_index');
        }
        $existing = $this->em->getRepository(EmailWhitelist::class)->findOneBy(['whitelistemail' => $email]);
        if (!$existing) {
            $entry = new EmailWhitelist();
            $entry->setEmail($this->config->get('email'));
            $entry->setWhitelistemail($email);
            $entry->setPatternType($patternType);
            $this->em->persist($entry);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_emailwhitelist_index');
    }

    #[Route('/del/{id}', name: 'antispam_emailwhitelist_del')]
    public function delAction($id)
    {
        $entry = $this->em->getRepository(EmailWhitelist::class)->find($id);
        if ($entry) {
            $this->em->remove($entry);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_emailwhitelist_index');
    }
}
