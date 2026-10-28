<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\RawMessageScanner;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Endpoints used by the Thunderbird plugin (see docs/thunderbird.md).
 *
 *   - anyone with the plugin can report spam (when plugin.anonymous_reports
 *     is on) — the report feeds the shared spam fingerprints;
 *   - users logged in with their mailbox credentials additionally get
 *     on-arrival checks (/check) and per-account rule learning.
 *
 * Routes are exempt from form login (security.yml: ^/api/plugin and
 * ^/plugin/download); auth is a bearer token issued by /api/plugin/login.
 */
class PluginApiController extends AbstractController
{
    public function __construct(
        private RawMessageScanner $rawScanner,
        private PluginService $plugin,
        private DeferredRetroactivePass $retroactive,
        private EntityManagerInterface $em,
        private PhishingReportService $phishing,
    ) {
    }

    /** Retroactive passes (IMAP/SSH login each) per account and hour. */
    const RETRO_RATE_LIMIT = 10;
    /** Phishing reports (full messages up to 10 MiB each) per account and hour. */
    const PHISHING_RATE_LIMIT = 30;

    const PLUGIN_VERSION = '1.1.2';

    #[Route('/plugin/download', name: 'antispam_plugin_download', methods: ['GET'])]
    public function downloadAction(Request $request)
    {
        if (!$this->plugin->isEnabled()) {
            throw $this->createNotFoundException('Thunderbird plugin is disabled');
        }
        if (!class_exists(\ZipArchive::class)) {
            return new Response('PHP zip extension is required to build the plugin', 500);
        }

        $server = $this->plugin->getPublicUrl() ?: $request->getSchemeAndHttpHost() . $request->getBasePath();
        $src = __DIR__ . '/../Resources/thunderbird';
        $tmp = tempnam(sys_get_temp_dir(), 'tbxpi');

        $zip = new \ZipArchive();
        $zip->open($tmp, \ZipArchive::OVERWRITE);
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($src, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($src) + 1));
            if ($rel === 'manifest.json') {
                $zip->addFromString($rel, $this->buildManifest($file->getPathname(), $server));
            } elseif ($rel !== 'config.json') {
                $zip->addFile($file->getPathname(), $rel);
            }
        }
        // Pre-configured server URL, so the user never has to type it.
        $zip->addFromString('config.json', json_encode(['server' => $server], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        $zip->close();

        // Built per request with the current code: never let a browser or proxy keep an old .xpi.
        $response = new BinaryFileResponse($tmp, 200, [], false);
        $response->headers->set('Content-Type', 'application/x-xpinstall');
        $response->headers->set('Cache-Control', 'private, no-store');
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, 'antispam-thunderbird.xpi');
        $response->deleteFileAfterSend(true);
        return $response;
    }

    #[Route('/api/plugin/status', name: 'antispam_plugin_api_status', methods: ['GET'])]
    public function statusAction(Request $request)
    {
        $account = $this->plugin->accountForToken($this->bearer($request));

        return new JsonResponse([
            'enabled' => $this->plugin->isEnabled(),
            'version' => self::PLUGIN_VERSION,
            'anonymous_reports' => $this->plugin->isAnonymousReportEnabled(),
            'check_enabled' => $this->plugin->isCheckEnabled(),
            'phishing_reports' => true,
            'phishing_max_bytes' => PhishingReportService::MAX_RAW_BYTES,
            // Largest message source (decoded) the plugins should send in one request -
            // reflects the body limit of a proxy in front of antispam (plugin.max_upload_kb).
            'max_upload_bytes' => $this->plugin->getMaxUploadBytes(),
            'authenticated' => $account !== null,
            'email' => $account ? $account->getEmail() : null,
        ]);
    }

    /** POST {"email": "...", "password": "..."} → {"token", "email", "expires_at"} */
    #[Route('/api/plugin/login', name: 'antispam_plugin_api_login', methods: ['POST'])]
    public function loginAction(Request $request)
    {
        if (!$this->plugin->isEnabled()) {
            return new JsonResponse(['error' => 'plugin disabled'], 403);
        }
        if (!$this->plugin->hit('login', $this->clientIp($request), PluginService::LOGIN_RATE_LIMIT, 900)) {
            return new JsonResponse(['error' => 'too many attempts, try again later'], 429);
        }

        $data = json_decode($request->getContent(), true);
        $account = $this->plugin->authenticate($data['email'] ?? '', $data['password'] ?? '');
        if (!$account) {
            return new JsonResponse(['error' => 'invalid e-mail or password'], 401);
        }

        $token = $this->plugin->issueToken($account);
        return new JsonResponse([
            'token' => $token['token'],
            'email' => $account->getEmail(),
            'expires_at' => date(\DateTime::ATOM, $token['expires_at']),
        ]);
    }

    /**
     * User verdict on a message. POST {"raw_base64": "...", "verdict": "spam|ham"}
     * Token optional for "spam" (anonymous report), required for "ham".
     */
    #[Route('/api/plugin/report', name: 'antispam_plugin_api_report', methods: ['POST'])]
    public function reportAction(Request $request)
    {
        if (!$this->plugin->isEnabled()) {
            return new JsonResponse(['error' => 'plugin disabled'], 403);
        }
        $account = $this->plugin->accountForToken($this->bearer($request));
        if (!$account && !$this->plugin->isAnonymousReportEnabled()) {
            return new JsonResponse(['error' => 'login required'], 401);
        }
        $data = json_decode($request->getContent(), true);
        $verdict = $data['verdict'] ?? PluginService::VERDICT_SPAM;
        if (!in_array($verdict, [PluginService::VERDICT_SPAM, PluginService::VERDICT_HAM], true)) {
            return new JsonResponse(['error' => 'invalid verdict'], 400);
        }
        if ($verdict === PluginService::VERDICT_HAM && !$account) {
            // Anonymous "not spam" would let spammers whitelist themselves.
            return new JsonResponse(['error' => 'login required for not-spam reports'], 401);
        }
        if (($raw = $this->rawFrom($data)) instanceof JsonResponse) {
            return $raw;
        }
        // Counted only for valid reports: a malformed request must not use up the budget.
        if (!$this->plugin->hit('report', $account ? 'acc:' . $account->getId() : $this->clientIp($request), $this->plugin->getReportRateLimit(), 3600)) {
            return new JsonResponse(['error' => 'rate limit exceeded'], 429);
        }

        $result = $this->plugin->learn($raw, $verdict, $account, $this->clientIp($request));
        $result['authenticated'] = $account !== null;
        if ($account) {
            $this->applyRetroactive($account, $result);
        }
        return new JsonResponse($result);
    }

    /**
     * Phishing attempt: handled like a spam report (sender blacklisted, shared
     * fingerprints) and the full message is kept for the admin on the
     * "Zgłoszenia phishingu" page. POST {"raw_base64": "...", "client":
     * "thunderbird|outlook", "truncated": bool}. Login required - the message
     * content is stored.
     */
    #[Route('/api/plugin/phishing', name: 'antispam_plugin_api_phishing', methods: ['POST'])]
    public function phishingAction(Request $request)
    {
        if (!$this->plugin->isEnabled()) {
            return new JsonResponse(['error' => 'plugin disabled'], 403);
        }
        $account = $this->plugin->accountForToken($this->bearer($request));
        if (!$account) {
            return new JsonResponse(['error' => 'login required'], 401);
        }
        $data = json_decode($request->getContent(), true);
        if (($raw = $this->rawFrom($data, PhishingReportService::MAX_RAW_BYTES)) instanceof JsonResponse) {
            return $raw;
        }
        // Validated first, then counted. Also counts against the spam report
        // budget: it feeds learn() / the shared feed too.
        if (!$this->plugin->hit('phishing', 'acc:' . $account->getId(), self::PHISHING_RATE_LIMIT, 3600)
            || !$this->plugin->hit('report', 'acc:' . $account->getId(), $this->plugin->getReportRateLimit(), 3600)) {
            return new JsonResponse(['error' => 'rate limit exceeded'], 429);
        }

        try {
            $stored = $this->phishing->submit($raw, $account, (string)($data['client'] ?? ''), $this->clientIp($request), !empty($data['truncated']));
        } catch (\OverflowException $e) {
            // The admin has to review / delete older reports of this mailbox first.
            return new JsonResponse(['error' => 'phishing report quota exceeded'], 507);
        }
        $result = $this->plugin->learn($raw, PluginService::VERDICT_SPAM, $account, $this->clientIp($request));
        $result['authenticated'] = true;
        $result['phishing_id'] = $stored['id'];
        $result['duplicate'] = $stored['duplicate'];
        $this->applyRetroactive($account, $result);
        return new JsonResponse($result);
    }

    /**
     * A newly blacklisted sender: older mail from them leaves INBOX too.
     * It logs in to the mailbox (IMAP/SSH), so it has its own, tighter limit;
     * over the limit the rule still applies to new mail on the next scan.
     *
     * The pass runs after the response is sent (DeferredRetroactivePass), so
     * a slow mailbox never delays the plugin; how many messages it moved is
     * not known here - "retroactive": "scheduled" only says it will run.
     */
    private function applyRetroactive(Account $account, array &$result)
    {
        if (in_array('email_blacklist_added:' . $result['sender'], $result['rules'], true)
            && $this->plugin->hit('retro', 'acc:' . $account->getId(), self::RETRO_RATE_LIMIT, 3600)) {
            $rule = $this->em->getRepository(EmailBlacklist::class)->findOneBy([
                'email' => $account->getEmail(), 'blacklistemail' => $result['sender'], 'patternType' => 'exact',
            ]);
            if ($rule) {
                $this->retroactive->defer($rule);
                $result['retroactive'] = 'scheduled';
            }
        }
    }

    /** Score a newly arrived message. POST {"raw_base64": "..."} (token required) */
    #[Route('/api/plugin/check', name: 'antispam_plugin_api_check', methods: ['POST'])]
    public function checkAction(Request $request)
    {
        if (!$this->plugin->isEnabled() || !$this->plugin->isCheckEnabled()) {
            return new JsonResponse(['error' => 'checks disabled'], 403);
        }
        $account = $this->plugin->accountForToken($this->bearer($request));
        if (!$account) {
            return new JsonResponse(['error' => 'login required'], 401);
        }

        $data = json_decode($request->getContent(), true);
        if (($raw = $this->rawFrom($data)) instanceof JsonResponse) {
            return $raw;
        }

        return new JsonResponse($this->rawScanner->scan($raw, $account->getEmail()));
    }

    /** @return string|JsonResponse decoded message source or an error response */
    private function rawFrom($data, $maxBytes = PluginService::MAX_RAW_BYTES)
    {
        $b64 = is_array($data) ? (string)($data['raw_base64'] ?? '') : '';
        $raw = $b64 === '' ? false : base64_decode($b64, true);
        if ($raw === false || $raw === '') {
            return new JsonResponse(['error' => 'missing or invalid raw_base64'], 400);
        }
        if (strlen($raw) > $maxBytes) {
            return new JsonResponse(['error' => 'message too large'], 413);
        }
        return $raw;
    }

    /**
     * Client IP for rate limiting. Behind a reverse proxy on a private network
     * (Docker / Coolify, no trusted_proxies configured) every request comes from
     * the proxy, so use the address the proxy appended to X-Forwarded-For —
     * the rightmost entry, which the client cannot forge.
     */
    private function clientIp(Request $request)
    {
        $ip = (string)$request->server->get('REMOTE_ADDR', '');
        $isPublic = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        $xff = (string)$request->headers->get('X-Forwarded-For', '');
        if (!$isPublic && $xff !== '') {
            $hops = array_map('trim', explode(',', $xff));
            $last = end($hops);
            if (filter_var($last, FILTER_VALIDATE_IP)) {
                return $last;
            }
        }
        return $ip;
    }

    private function bearer(Request $request)
    {
        $h = (string)$request->headers->get('Authorization', '');
        return stripos($h, 'Bearer ') === 0 ? trim(substr($h, 7)) : '';
    }

    /** Manifest with the server origin added to host permissions. */
    private function buildManifest($path, $server)
    {
        $manifest = json_decode(file_get_contents($path), true);
        $parts = parse_url($server);
        if (!empty($parts['scheme']) && !empty($parts['host'])) {
            // Match patterns cannot carry a port; the host alone covers every port.
            $manifest['permissions'][] = $parts['scheme'] . '://' . $parts['host'] . '/*';
            if ($parts['scheme'] === 'http') {
                // The proxy may redirect http:// to https:// — without this the
                // redirected request is blocked as cross-origin.
                $manifest['permissions'][] = 'https://' . $parts['host'] . '/*';
            }
            $manifest['permissions'] = array_values(array_unique($manifest['permissions']));
        }
        return json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
