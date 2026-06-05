<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\SharedSpamSignal;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Hub side of the centralized spam DB. Other instances (and this instance's own
 * `antispam:feed:sync` command) report and pull spam fingerprints here.
 *
 * Auth is a shared secret presented in the `X-Feed-Key` header, matched against
 * the `feed.server_key` config value. When that value is empty the API is
 * considered disabled and every request is rejected. These routes are exempt
 * from the form-login firewall via security.yml (^/api/feed).
 *
 * @Route("/api/feed")
 */
class SpamFeedApiController extends Controller
{
    /** Hard cap on accepted signals per POST — protects the DB from a flood. */
    const MAX_SIGNALS_PER_REPORT = 1000;

    /** Hard cap on raw request body size (bytes) before we even json_decode. */
    const MAX_REPORT_BYTES = 262144;

    /**
     * Receive a batch of signals from another instance.
     *
     * POST body: {"signals": [{"type": "sender|body", "hash": "<sha256>"}, ...]}
     *
     * @Route("/report", name="antispam_feed_api_report", methods={"POST"})
     */
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

        $feed = $this->get('antispam.spam_signal');
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
     * Serve signals updated since a timestamp (incremental pull).
     *
     * GET /api/feed/pull?since=<ISO8601>&limit=<n>
     *
     * @Route("/pull", name="antispam_feed_api_pull", methods={"GET"})
     */
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
        }
        $limit = min(5000, max(1, (int)$request->query->get('limit', 5000)));

        $repo = $this->getDoctrine()->getManager()->getRepository(SharedSpamSignal::class);
        $signals = [];
        foreach ($repo->findUpdatedSince($since, $limit) as $s) {
            $signals[] = [
                'type' => $s->getType(),
                'hash' => $s->getHash(),
                'reports' => $s->getReports(),
                'updated_at' => $s->getUpdatedAt()->format(\DateTime::ATOM),
            ];
        }

        return new JsonResponse([
            'signals' => $signals,
            'count' => count($signals),
            'now' => (new \DateTime())->format(\DateTime::ATOM),
        ]);
    }

    /**
     * Lightweight health/stats endpoint (also confirms the key works).
     *
     * @Route("/stats", name="antispam_feed_api_stats", methods={"GET"})
     */
    public function statsAction(Request $request)
    {
        if (($deny = $this->denyUnlessAuthorized($request)) !== null) {
            return $deny;
        }
        $repo = $this->getDoctrine()->getManager()->getRepository(SharedSpamSignal::class);
        return new JsonResponse(['signals' => $repo->countByOrigin()]);
    }

    /**
     * @return JsonResponse|null JsonResponse to short-circuit with, or null when authorized.
     */
    private function denyUnlessAuthorized(Request $request)
    {
        $serverKey = $this->get('antispam.spam_signal')->getServerKey();
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
