<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\Jobs\JobQueue;
use AntispamBundle\Services\ScoringService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

/** CERT Polska "Lista Ostrzeżeń" (hole.cert.pl): settings, manual sync, lookup. */
#[Route('/cert')]
class CertController extends AbstractController
{
    use AuditTrait;
    use JobQueueTrait;

    const PER_PAGE = 50;

    public function __construct(
        private EntityManagerInterface $em,
        private CertHoleService $cert,
        private ConfigService $config,
        private ScoringService $scoring,
        private JobQueue $jobs,
    ) {
    }

    #[Route('/', name: 'antispam_cert_index', methods: ['GET', 'POST'])]
    #[Template('@Antispam/Cert/index.html.twig')]
    public function indexAction(Request $request)
    {
        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('cert_config', (string)$request->request->get('_token'))) {
                throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
            }
            $post = $request->request->all('config');
            $this->config->set('cert.enabled', array_key_exists('enabled', $post) ? '1' : '0');
            $score = trim((string)($post['score'] ?? ''));
            $this->config->set('cert.score', $score === '' ? '' : (string)max(1, (int)$score));
            $this->audit('settings.save', targetType: 'settings', targetId: 'cert', label: 'Lista CERT', details: ['enabled' => array_key_exists('enabled', $post), 'score' => $this->config->get('cert.score')]);
            $this->addFlash('success', 'Ustawienia listy CERT zapisane');
            return $this->redirectToRoute('antispam_cert_index');
        }

        $conn = $this->em->getConnection();
        $page = max(1, $request->query->getInt('page', 1));
        $total = $this->cert->countDomains();
        $pages = max(1, (int)ceil($total / self::PER_PAGE));
        $page = min($page, $pages);
        $sample = [];
        try {
            $sample = $conn->fetchFirstColumn(
                'SELECT domain FROM antispam_cert_domain ORDER BY domain LIMIT ' . (int)self::PER_PAGE . ' OFFSET ' . (int)(($page - 1) * self::PER_PAGE)
            );
        } catch (\Throwable $e) {
        }

        $query = trim((string)$request->query->get('q', ''));
        $lookup = null;
        if ($query !== '') {
            $authority = explode('/', preg_replace('~^[a-z]+://~i', '', $query))[0];
            $host = CertHoleService::normalizeDomain(preg_replace('/:\d+$/', '', substr(strrchr('@' . $authority, '@'), 1)));
            $candidates = CertHoleService::candidates($host);
            $listed = $candidates ? $this->cert->findListed($candidates) : [];
            $lookup = [
                'input' => $query,
                'valid' => $host !== '',
                'host' => $host,
                'match' => $listed ? array_key_first(array_intersect_key(array_flip($candidates), $listed)) : null,
            ];
        }

        return [
            'enabled' => $this->cert->isEnabled(),
            'score' => $this->config->get('cert.score') ?: '',
            'default_score' => $this->scoring->getSpamThreshold(),
            'status' => $this->cert->getStatus(),
            'total' => $total,
            'sample' => $sample,
            'page' => $page,
            'pages' => $pages,
            'query' => $query,
            'lookup' => $lookup,
            'url' => $this->cert->getUrl(),
        ];
    }

    #[Route('/sync', name: 'antispam_cert_sync', methods: ['POST'])]
    public function syncAction(Request $request)
    {
        if (!$this->isCsrfTokenValid('cert_config', (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
        // Download + replace of the whole list: background job (docs/jobs.md).
        $queued = $this->jobs->enqueue(BackgroundJob::TYPE_CERT_SYNC, dedupeKey: BackgroundJob::TYPE_CERT_SYNC);
        return $this->redirectToJob($queued, 'Synchronizacja listy CERT');
    }
}
