<?php

namespace AntispamBundle\Controller;

use AntispamBundle\AppVersion;
use AntispamBundle\Services\SimpleMarkdown;
use AntispamBundle\Services\SshService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/** "Co nowego": the running version and CHANGELOG.md rendered as HTML (admins only). */
#[IsGranted('ROLE_ADMIN')]
class ChangelogController extends AbstractController
{
    public function __construct(
        private AppVersion $version,
        private SimpleMarkdown $markdown,
        #[Autowire('%kernel.project_dir%/CHANGELOG.md')]
        private string $changelogFile,
    ) {
    }

    #[Route('/changelog', name: 'antispam_changelog', methods: ['GET'])]
    public function indexAction(): Response
    {
        $source = is_file($this->changelogFile) ? (string) file_get_contents($this->changelogFile) : '';

        return $this->render('@Antispam/Changelog/index.html.twig', [
            'version' => $this->version,
            'agent_version' => SshService::bundledAgentVersion(),
            'changelog_html' => $source !== '' ? $this->markdown->render($source) : null,
        ]);
    }
}
