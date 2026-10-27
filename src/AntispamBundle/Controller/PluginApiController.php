<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Services\PluginService;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

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
class PluginApiController extends Controller
{
    const PLUGIN_VERSION = '1.0.0';

    /**
     * @Route("/plugin/download", name="antispam_plugin_download", methods={"GET"})
     */
    public function downloadAction(Request $request)
    {
        $plugin = $this->plugin();
        if (!$plugin->isEnabled()) {
            throw $this->createNotFoundException('Thunderbird plugin is disabled');
        }
        if (!class_exists(\ZipArchive::class)) {
            return new Response('PHP zip extension is required to build the plugin', 500);
        }

        $server = $plugin->getPublicUrl() ?: $request->getSchemeAndHttpHost() . $request->getBasePath();
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

        $response = new BinaryFileResponse($tmp);
        $response->headers->set('Content-Type', 'application/x-xpinstall');
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, 'antispam-thunderbird.xpi');
        $response->deleteFileAfterSend(true);
        return $response;
    }

    /**
     * @Route("/api/plugin/status", name="antispam_plugin_api_status", methods={"GET"})
     */
    public function statusAction(Request $request)
    {
        $plugin = $this->plugin();
        $account = $plugin->accountForToken($this->bearer($request));

        return new JsonResponse([
            'enabled' => $plugin->isEnabled(),
            'version' => self::PLUGIN_VERSION,
            'anonymous_reports' => $plugin->isAnonymousReportEnabled(),
            'check_enabled' => $plugin->isCheckEnabled(),
            'authenticated' => $account !== null,
            'email' => $account ? $account->getEmail() : null,
        ]);
    }

    /**
     * POST {"email": "...", "password": "..."} → {"token", "email", "expires_at"}
     *
     * @Route("/api/plugin/login", name="antispam_plugin_api_login", methods={"POST"})
     */
    public function loginAction(Request $request)
    {
        $plugin = $this->plugin();
        if (!$plugin->isEnabled()) {
            return new JsonResponse(['error' => 'plugin disabled'], 403);
        }
        if (!$plugin->hit('login', $this->clientIp($request), PluginService::LOGIN_RATE_LIMIT, 900)) {
            return new JsonResponse(['error' => 'too many attempts, try again later'], 429);
        }

        $data = json_decode($request->getContent(), true);
        $account = $plugin->authenticate($data['email'] ?? '', $data['password'] ?? '');
        if (!$account) {
            return new JsonResponse(['error' => 'invalid e-mail or password'], 401);
        }

        $token = $plugin->issueToken($account);
        return new JsonResponse([
            'token' => $token['token'],
            'email' => $account->getEmail(),
            'expires_at' => date(\DateTime::ATOM, $token['expires_at']),
        ]);
    }

    /**
     * User verdict on a message. POST {"raw_base64": "...", "verdict": "spam|ham"}
     * Token optional for "spam" (anonymous report), required for "ham".
     *
     * @Route("/api/plugin/report", name="antispam_plugin_api_report", methods={"POST"})
     */
    public function reportAction(Request $request)
    {
        $plugin = $this->plugin();
        if (!$plugin->isEnabled()) {
            return new JsonResponse(['error' => 'plugin disabled'], 403);
        }
        $account = $plugin->accountForToken($this->bearer($request));
        if (!$account && !$plugin->isAnonymousReportEnabled()) {
            return new JsonResponse(['error' => 'login required'], 401);
        }
        if (!$plugin->hit('report', $account ? 'acc:' . $account->getId() : $this->clientIp($request), $plugin->getReportRateLimit(), 3600)) {
            return new JsonResponse(['error' => 'rate limit exceeded'], 429);
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

        $result = $plugin->learn($raw, $verdict, $account);
        $result['authenticated'] = $account !== null;
        return new JsonResponse($result);
    }

    /**
     * Score a newly arrived message. POST {"raw_base64": "..."} (token required)
     *
     * @Route("/api/plugin/check", name="antispam_plugin_api_check", methods={"POST"})
     */
    public function checkAction(Request $request)
    {
        $plugin = $this->plugin();
        if (!$plugin->isEnabled() || !$plugin->isCheckEnabled()) {
            return new JsonResponse(['error' => 'checks disabled'], 403);
        }
        $account = $plugin->accountForToken($this->bearer($request));
        if (!$account) {
            return new JsonResponse(['error' => 'login required'], 401);
        }

        $data = json_decode($request->getContent(), true);
        if (($raw = $this->rawFrom($data)) instanceof JsonResponse) {
            return $raw;
        }

        return new JsonResponse($this->get('antispam.raw_scanner')->scan($raw, $account->getEmail()));
    }

    /** @return string|JsonResponse decoded message source or an error response */
    private function rawFrom($data)
    {
        $b64 = is_array($data) ? (string)($data['raw_base64'] ?? '') : '';
        $raw = $b64 === '' ? false : base64_decode($b64, true);
        if ($raw === false || $raw === '') {
            return new JsonResponse(['error' => 'missing or invalid raw_base64'], 400);
        }
        if (strlen($raw) > PluginService::MAX_RAW_BYTES) {
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
            $origin = $parts['scheme'] . '://' . $parts['host'] . '/*';
            $manifest['permissions'][] = $origin;
            $manifest['permissions'] = array_values(array_unique($manifest['permissions']));
        }
        return json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /** @return PluginService */
    private function plugin()
    {
        return $this->get('antispam.plugin');
    }
}
