<?php

namespace AntispamBundle\Controller;

use AntispamBundle\AppVersion;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\RawMessageScanner;
use AntispamBundle\Services\ThunderbirdPluginBuilder;
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
 * ^/plugin/(download|thunderbird/|setup)); auth is a bearer token issued by /api/plugin/login.
 */
class PluginApiController extends AbstractController
{
    use AuditTrait;

    private ThunderbirdPluginBuilder $tb;

    public function __construct(
        private RawMessageScanner $rawScanner,
        private PluginService $plugin,
        private DeferredRetroactivePass $retroactive,
        private EntityManagerInterface $em,
        private PhishingReportService $phishing,
        ?ThunderbirdPluginBuilder $tb = null,
    ) {
        $this->tb = $tb ?? new ThunderbirdPluginBuilder();
    }

    /** Retroactive passes (IMAP/SSH login each) per account and hour. */
    const RETRO_RATE_LIMIT = 10;
    /** Phishing reports (full messages up to 10 MiB each) per account and hour. */
    const PHISHING_RATE_LIMIT = 30;

    const PLUGIN_VERSION = '1.2.0';

    /**
     * The Thunderbird .xpi. Default: the uploaded generic package (e.g. the
     * file from addons.thunderbird.net) when one of the current version is
     * stored, otherwise the instance build (server URL in config.json, self-hosted
     * updates). ?build=instance / ?build=generic force a variant.
     */
    #[Route('/plugin/download', name: 'antispam_plugin_download', methods: ['GET'])]
    public function downloadAction(Request $request)
    {
        if (!$this->plugin->isEnabled()) {
            throw $this->createNotFoundException('Thunderbird plugin is disabled');
        }
        if (!class_exists(\ZipArchive::class)) {
            return new Response('PHP zip extension is required to build the plugin', 500);
        }

        $build = (string)$request->query->get('build', '');
        $uploaded = $build === 'instance' ? null : $this->tb->uploadedBuild();
        if ($uploaded && $uploaded['current']) {
            $response = new BinaryFileResponse($uploaded['path'], 200, [], false);
            $name = 'antispam-thunderbird-' . $uploaded['version'] . '.xpi';
        } else {
            $server = $build === 'generic' ? null : $this->baseUrl($request);
            $response = new BinaryFileResponse($this->tb->buildTemp($server), 200, [], false);
            $response->deleteFileAfterSend(true);
            $name = $server === null ? 'antispam-thunderbird-generic.xpi' : 'antispam-thunderbird.xpi';
        }
        // Built per request with the current code: never let a browser or proxy keep an old .xpi.
        $response->headers->set('Content-Type', 'application/x-xpinstall');
        $response->headers->set('Cache-Control', 'private, no-store');
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, $name);
        return $response;
    }

    /**
     * Self-hosted update manifest (update_url of the instance build, https only).
     * Points at the instance build, so an update keeps the baked-in server URL.
     */
    #[Route('/plugin/thunderbird/updates.json', name: 'antispam_plugin_thunderbird_updates', methods: ['GET'])]
    public function updatesAction(Request $request)
    {
        if (!$this->plugin->isEnabled()) {
            throw $this->createNotFoundException('Thunderbird plugin is disabled');
        }
        $link = $this->baseUrl($request) . '/plugin/download?build=instance&v=' . rawurlencode(self::PLUGIN_VERSION);
        $response = new JsonResponse($this->tb->updatesManifest($link));
        $response->setEncodingOptions(JsonResponse::DEFAULT_ENCODING_OPTIONS | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        $response->headers->set('Cache-Control', 'public, max-age=300');
        return $response;
    }

    /**
     * Public setup page: the server address to paste into a generic plugin
     * build (first run), with install steps. Linked from the panel.
     */
    #[Route('/plugin/setup', name: 'antispam_plugin_setup', methods: ['GET'])]
    public function setupAction(Request $request)
    {
        if (!$this->plugin->isEnabled()) {
            throw $this->createNotFoundException('Mail client plugins are disabled');
        }
        $response = $this->render('@Antispam/Configuration/pluginSetup.html.twig', [
            'server' => $this->baseUrl($request),
            'version' => self::PLUGIN_VERSION,
        ]);
        $response->headers->set('X-Robots-Tag', 'noindex');
        return $response;
    }

    private function baseUrl(Request $request): string
    {
        return rtrim($this->plugin->getPublicUrl() ?: $request->getSchemeAndHttpHost() . $request->getBasePath(), '/');
    }

    #[Route('/api/plugin/status', name: 'antispam_plugin_api_status', methods: ['GET'])]
    public function statusAction(Request $request)
    {
        $account = $this->plugin->accountForToken($this->bearer($request));

        return new JsonResponse([
            'enabled' => $this->plugin->isEnabled(),
            'version' => self::PLUGIN_VERSION,
            // Version of this antispam server (AppVersion), lets plugins and
            // admins tell which release a host runs.
            'server_version' => AppVersion::VERSION,
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

    /**
     * Connection test from the plugin settings ("Testuj połączenie"). POST
     * {"client": "thunderbird", "client_version": "...", "app": "Thunderbird 153"}.
     * Nothing is learned; the call is written to the audit log (plugin.ping),
     * so the admin sees in the panel that the plugin reached this server.
     */
    #[Route('/api/plugin/ping', name: 'antispam_plugin_api_ping', methods: ['POST'])]
    public function pingAction(Request $request)
    {
        if (!$this->plugin->hit('ping', $this->clientIp($request), 60, 3600)) {
            return new JsonResponse(['error' => 'rate limit exceeded'], 429);
        }
        $account = $this->plugin->accountForToken($this->bearer($request));
        $data = json_decode($request->getContent(), true);
        $data = is_array($data) ? $data : [];
        $clip = static fn($v) => mb_substr(is_scalar($v) ? (string)$v : '', 0, 80);
        $details = ['client' => $clip($data['client'] ?? ''), 'client_version' => $clip($data['client_version'] ?? ''), 'app' => $clip($data['app'] ?? ''), 'authenticated' => $account !== null];

        $this->audit('plugin.ping', targetType: 'plugin', label: trim($details['client'] . ' ' . $details['client_version']), mailbox: $account?->getEmail(), details: $details,
            actor: $account ? $account->getEmail() : 'wtyczka (anonim)', actorType: $account ? AuditLog::ACTOR_PLUGIN : AuditLog::ACTOR_ANONYMOUS);

        return new JsonResponse([
            'ok' => true,
            'enabled' => $this->plugin->isEnabled(),
            'server_version' => AppVersion::VERSION,
            'plugin_version' => self::PLUGIN_VERSION,
            'authenticated' => $account !== null,
            'email' => $account ? $account->getEmail() : null,
            'client_ip' => $this->clientIp($request),
            'received_at' => (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM),
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
            $this->audit('plugin.login_failed', targetType: 'account', mailbox: $typed = mb_substr(is_scalar($data['email'] ?? null) ? (string)$data['email'] : '', 0, 180), actor: $typed !== '' ? $typed : 'wtyczka', actorType: AuditLog::ACTOR_ANONYMOUS);
            return new JsonResponse(['error' => 'invalid e-mail or password'], 401);
        }

        $token = $this->plugin->issueToken($account);
        $this->audit('plugin.login', targetType: 'account', targetId: $account->getId(), mailbox: $account->getEmail(), actor: $account->getEmail(), actorType: AuditLog::ACTOR_PLUGIN);
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
        $this->audit('plugin.report', targetType: 'message', label: (string)($result['sender'] ?? ''), mailbox: $account?->getEmail(), details: ['verdict' => $verdict, 'rules' => $result['rules'] ?? []],
            actor: $account ? $account->getEmail() : 'wtyczka (anonim)', actorType: $account ? AuditLog::ACTOR_PLUGIN : AuditLog::ACTOR_ANONYMOUS);
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
        $result = $this->plugin->learn($raw, PluginService::VERDICT_SPAM, $account, $this->clientIp($request), 'phishing');
        $result['authenticated'] = true;
        $result['phishing_id'] = $stored['id'];
        $this->audit('plugin.phishing', targetType: 'phishing', targetId: $stored['id'], label: (string)($result['sender'] ?? ''), mailbox: $account->getEmail(), details: ['duplicate' => (bool)$stored['duplicate'], 'client' => is_scalar($data['client'] ?? null) ? mb_substr((string)$data['client'], 0, 20) : ''],
            actor: $account->getEmail(), actorType: AuditLog::ACTOR_PLUGIN);
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

        return new JsonResponse($this->rawScanner->scan($raw, $account->getEmail(), $account));
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
}
