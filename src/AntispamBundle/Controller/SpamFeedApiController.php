<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\SharedSpamSignal;
use AntispamBundle\Services\SpamSignalService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Hub side of the centralized spam DB. Other instances (and this instance's own
 * `antispam:feed:sync` command) report and pull spam fingerprints here.
 *
 * Auth is a shared secret presented in the `X-Feed-Key` header, matched against
 * the `feed.server_key` config value. When that value is empty the API is
 * considered disabled and every request is rejected. These routes are exempt
 * from the form-login firewall via security.yml (^/api/feed).
 */
#[Route('/api/feed')]
class SpamFeedApiController extends AbstractController
{
    /** Upper bounds for one /report call, so a peer cannot flood the database. */
    const MAX_SIGNALS_PER_REPORT = 1000;
    const MAX_REPORT_BYTES = 262144;
    /** Page size cap of one /pull call. */
    const MAX_SIGNALS_PER_PULL = 5000;

    public function __construct(
        private EntityManagerInterface $em,
        private SpamSignalService $feed,
    ) {
    }

    /**
     * Receive a batch of signals from another instance.
     *
     * POST body: {"signals": [{"type": "sender|body", "hash": "<sha256>"}, ...]}
     */
    #[Route('/report', name: 'antispam_feed_api_report', methods: ['POST'])]
    public function reportAction(Request $request)
    {
        if (($deny = $this->denyUnlessAuthorized($request)) !== null) {
            return $deny;
        }

        $body = $request->getContent();
        if (strlen($body) > self::MAX_REPORT_BYTES) {
            return new JsonResponse(['error' => 'payload too large'], 413);
        }
        $payload = json_decode($body, true);
        if (!is_array($payload) || !isset($payload['signals']) || !is_array($payload['signals'])) {
            return new JsonResponse(['error' => 'invalid payload'], 400);
        }
        if (count($payload['signals']) > self::MAX_SIGNALS_PER_REPORT) {
            return new JsonResponse(['error' => 'too many signals'], 413);
        }

        $feed = $this->feed;
        $clean = [];
        foreach ($payload['signals'] as $sig) {
            if (is_array($sig) && $feed->isValidType($sig['type'] ?? null) && $feed->isValidHash($sig['hash'] ?? null)) {
                $clean[] = ['type' => $sig['type'], 'hash' => $sig['hash']];
            }
        }

        $accepted = $feed->record($clean, SharedSpamSignal::ORIGIN_REMOTE);
        $feed->flush();

        return new JsonResponse([
            'accepted' => $accepted,
            'received' => count($payload['signals']),
        ]);
    }

    /**
     * Serve signals updated since a cursor (incremental, paginated pull).
     *
     * GET /api/feed/pull?since=<ISO8601>&after_id=<id>&limit=<n>
     *
     * Rows come ordered by (updated_at, id). When `count` equals `limit` there
     * may be more: ask again with the returned `next` cursor.
     */
    #[Route('/pull', name: 'antispam_feed_api_pull', methods: ['GET'])]
    public function pullAction(Request $request)
    {
        if (($deny = $this->denyUnlessAuthorized($request)) !== null) {
            return $deny;
        }

        $since = null;
        $sinceRaw = trim((string)$request->query->get('since', ''));
        if ($sinceRaw !== '') {
            try { $since = new \DateTime($sinceRaw); } catch (\Exception $e) {
                return new JsonResponse(['error' => 'invalid since'], 400);
            }
            // The datetime column has no zone: compare in the zone it was written in.
            $since->setTimezone(new \DateTimeZone(date_default_timezone_get()));
        }
        $afterId = max(0, (int)$request->query->get('after_id', 0));
        $limit = min(self::MAX_SIGNALS_PER_PULL, max(1, (int)$request->query->get('limit', self::MAX_SIGNALS_PER_PULL)));

        $repo = $this->em->getRepository(SharedSpamSignal::class);
        $signals = [];
        $last = null;
        foreach ($repo->findUpdatedSince($since, $limit, $afterId) as $s) {
            $signals[] = [
                'id' => $s->getId(),
                'type' => $s->getType(),
                'hash' => $s->getHash(),
                'reports' => $s->getReports(),
                'updated_at' => $s->getUpdatedAt()->format(\DateTime::ATOM),
            ];
            $last = $s;
        }

        return new JsonResponse([
            'signals' => $signals,
            'count' => count($signals),
            'limit' => $limit,
            'has_more' => count($signals) === $limit,
            'next' => $last ? ['since' => $last->getUpdatedAt()->format(\DateTime::ATOM), 'after_id' => $last->getId()] : null,
            'now' => (new \DateTime())->format(\DateTime::ATOM),
        ]);
    }

    /** Lightweight health/stats endpoint (also confirms the key works). */
    #[Route('/stats', name: 'antispam_feed_api_stats', methods: ['GET'])]
    public function statsAction(Request $request)
    {
        if (($deny = $this->denyUnlessAuthorized($request)) !== null) {
            return $deny;
        }
        $repo = $this->em->getRepository(SharedSpamSignal::class);
        return new JsonResponse(['signals' => $repo->countByOrigin()]);
    }

    /**
     * @return JsonResponse|null JsonResponse to short-circuit with, or null when authorized.
     */
    private function denyUnlessAuthorized(Request $request)
    {
        $serverKey = $this->feed->getServerKey();
        if ($serverKey === '') {
            return new JsonResponse(['error' => 'feed api disabled'], 403);
        }
        $presented = (string)$request->headers->get('X-Feed-Key', '');
        if (!hash_equals($serverKey, $presented)) {
            return new JsonResponse(['error' => 'unauthorized'], 401);
        }
        return null;
    }
}
