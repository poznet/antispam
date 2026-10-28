<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\HealthAlerter;
use AntispamBundle\Services\HealthMetrics;
use AntispamBundle\Services\HealthService;
use AntispamBundle\Services\HealthSettings;
use AntispamBundle\Services\Jobs\JobQueue;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Health endpoints and the "Stan systemu" admin page (docs/health.md).
 *
 *   GET /health          public: {"status": "ok|degraded|fail"} only, cached
 *                        PUBLIC_CACHE_TTL s; HTTP 503 when failing
 *   GET /health?token=   full report as JSON (also Authorization: Bearer)
 *   GET /metrics?token=  Prometheus text format
 */
class HealthController extends AbstractController
{
    use AuditTrait;
    use JobQueueTrait;

    const PUBLIC_CACHE_TTL = 30;
    const PUBLIC_CACHE_KEY = 'antispam_health_public';

    public function __construct(
        private HealthService $health,
        private HealthSettings $settings,
        private HealthAlerter $alerter,
        private HealthMetrics $metrics,
        private CacheInterface $cache,
        private ?JobQueue $jobs = null,
    ) {
    }

    #[Route('/health', name: 'antispam_health', methods: ['GET'])]
    public function healthAction(Request $request): Response
    {
        $token = self::requestToken($request);
        if ($token !== null) {
            if (!$this->settings->isValidToken($token)) {
                return $this->noStore(new JsonResponse(['error' => 'invalid token'], Response::HTTP_FORBIDDEN));
            }
            $report = $this->health->run($request->query->getBoolean('full'));
            return $this->noStore(new JsonResponse($report, self::httpStatus($report['status']), [], false));
        }

        // Anonymous: only the overall status, computed at most every
        // PUBLIC_CACHE_TTL seconds however often the monitor (or anyone) asks.
        $status = $this->cache->get(self::PUBLIC_CACHE_KEY, function (ItemInterface $item) {
            $item->expiresAfter(self::PUBLIC_CACHE_TTL);
            return $this->health->run(false)['status'];
        });
        return $this->noStore(new JsonResponse(['status' => $status], self::httpStatus($status)));
    }

    #[Route('/metrics', name: 'antispam_metrics', methods: ['GET'])]
    public function metricsAction(Request $request): Response
    {
        if (!$this->settings->isValidToken(self::requestToken($request))) {
            return $this->noStore(new Response("forbidden\n", Response::HTTP_FORBIDDEN, ['Content-Type' => 'text/plain; charset=utf-8']));
        }
        $body = $this->metrics->render($this->health->run(false));
        return $this->noStore(new Response($body, Response::HTTP_OK, ['Content-Type' => 'text/plain; version=0.0.4; charset=utf-8']));
    }

    /** ?job=ID shows the report of a finished "full check" job instead of a quick check. */
    #[Route('/system/status', name: 'antispam_system_status', methods: ['GET'])]
    public function statusAction(?Request $request = null): Response
    {
        $jobId = $request ? $request->query->getInt('job') : 0;
        if ($jobId > 0 && $this->jobs) {
            $job = $this->jobs->find($jobId);
            $report = $job && $job->getType() === BackgroundJob::TYPE_HEALTH_FULL ? $job->getResult() : null;
            if (is_array($report) && isset($report['checks'], $report['status'])) {
                return $this->renderPage($report);
            }
            $this->addFlash('warning', 'Wynik pełnego sprawdzenia nie jest (jeszcze) dostępny - poniżej szybkie sprawdzenie.');
        }
        return $this->renderPage($this->health->run(false));
    }

    #[Route('/system/status/check', name: 'antispam_system_status_check', methods: ['POST'])]
    public function checkAction(Request $request): Response
    {
        if (!$this->isCsrfTokenValid('health_check', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza - odśwież stronę i spróbuj ponownie.');
            return $this->redirectToRoute('antispam_system_status');
        }
        // IMAP logins and SSH agent queries take seconds per account: background job.
        if ($this->jobs) {
            $queued = $this->jobs->enqueue(BackgroundJob::TYPE_HEALTH_FULL, dedupeKey: BackgroundJob::TYPE_HEALTH_FULL);
            return $this->redirectToJob($queued, 'Pełne sprawdzenie stanu');
        }
        @set_time_limit(600);
        return $this->renderPage($this->health->run(true));
    }

    #[Route('/system/status/settings', name: 'antispam_system_status_settings', methods: ['POST'])]
    public function settingsAction(Request $request): Response
    {
        if (!$this->isCsrfTokenValid('health_settings', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza - odśwież stronę i spróbuj ponownie.');
            return $this->redirectToRoute('antispam_system_status');
        }
        $errors = $this->settings->save((array)$request->request->all('health'));
        if ($errors) {
            foreach ($errors as $error) {
                $this->addFlash('danger', $error);
            }
        } else {
            $this->audit('settings.save', targetType: 'settings', targetId: 'health', details: ['fields' => array_keys((array)$request->request->all('health'))]);
            $this->addFlash('success', 'Zapisano ustawienia alertów.');
        }
        return $this->redirectToRoute('antispam_system_status');
    }

    #[Route('/system/status/test-alert', name: 'antispam_system_status_test', methods: ['POST'])]
    public function testAlertAction(Request $request): Response
    {
        if (!$this->isCsrfTokenValid('health_settings', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza - odśwież stronę i spróbuj ponownie.');
            return $this->redirectToRoute('antispam_system_status');
        }
        [$sent, $errors] = $this->alerter->sendTest();
        if ($sent) {
            $this->addFlash('success', 'Wysłano testowy alert: ' . implode(', ', $sent) . '.');
        }
        foreach ($errors as $error) {
            $this->addFlash('danger', $error);
        }
        return $this->redirectToRoute('antispam_system_status');
    }

    private function renderPage(array $report): Response
    {
        $groups = [];
        foreach ($report['checks'] as $check) {
            $groups[$check['group']][] = $check;
        }
        return $this->render('@Antispam/Health/index.html.twig', [
            'report' => $report,
            'groups' => $groups,
            'group_labels' => ['system' => 'System', 'cron' => 'Zadania okresowe', 'accounts' => 'Konta pocztowe', 'services' => 'Usługi zewnętrzne'],
            'settings' => $this->settings,
            'alert_state' => $this->alerter->getState(),
            'has_channels' => $this->alerter->hasChannels(),
            'health_url' => $this->generateUrl('antispam_health', [], UrlGeneratorInterface::ABSOLUTE_URL),
            'metrics_url' => $this->generateUrl('antispam_metrics', [], UrlGeneratorInterface::ABSOLUTE_URL),
        ]);
    }

    /** Token from ?token= or "Authorization: Bearer ..." (Prometheus bearer_token). */
    private static function requestToken(Request $request): ?string
    {
        $token = $request->query->get('token');
        if (is_string($token) && $token !== '') {
            return $token;
        }
        $auth = (string)$request->headers->get('Authorization');
        if (stripos($auth, 'Bearer ') === 0) {
            $token = trim(substr($auth, 7));
            return $token === '' ? null : $token;
        }
        return null;
    }

    private static function httpStatus(string $status): int
    {
        return $status === HealthService::STATUS_FAIL ? Response::HTTP_SERVICE_UNAVAILABLE : Response::HTTP_OK;
    }

    private function noStore(Response $response): Response
    {
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('X-Robots-Tag', 'noindex');
        return $response;
    }
}
