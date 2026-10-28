<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\ImapFlags;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\ImapTlsProbe;
use AntispamBundle\Services\Jobs\JobQueue;
use AntispamBundle\Services\MailboxSettingsResolver;
use AntispamBundle\Services\OAuth\OAuthSettings;
use AntispamBundle\Services\RescanScheduler;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Mailbox accounts. Scan, agent deploy, rules sync and agent health run as
 * background jobs (docs/jobs.md): the buttons queue a job and redirect to its
 * page, so no panel request waits for a mailbox or an SSH server.
 */
#[Route('/account')]
class AccountController extends AbstractController
{
    use AuditTrait;
    use JobQueueTrait;

    /** "Test" stays synchronous, with short IMAP timeouts so it cannot hang the request. */
    const TEST_IMAP_OPEN_TIMEOUT = 10;
    const TEST_IMAP_READ_TIMEOUT = 20;

    public function __construct(
        private EntityManagerInterface $em,
        private SshService $ssh,
        private JobQueue $jobs,
        private ImapScanService $imapScan,
        private CryptoService $crypto,
        private ImapTlsProbe $tlsProbe,
        private ConfigService $config,
        private MailboxSettingsResolver $mailboxSettings,
        private ?OAuthSettings $oauthSettings = null,
        private ?RescanScheduler $rescans = null,
    ) {
    }

    /** Connection fields + per-mailbox settings ("Ustawienia skrzynki"). */
    private function validateForm(array $data): array
    {
        [, $settingsErrors] = $this->mailboxSettings->parseOverrides($data);
        return array_merge(self::validateAccountData($data), $settingsErrors, self::validateRescanData($data));
    }

    /**
     * Actions that change state or reach out to the mailbox server are POST
     * only and need the per-account CSRF token rendered in the account list.
     */
    private function checkActionToken(Request $request, string $tokenId)
    {
        if (!$request->isMethod('POST') || !$this->isCsrfTokenValid($tokenId, (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }

    #[Route('/index', name: 'antispam_account_index')]
    #[Template('@Antispam/Account/index.html.twig')]
    public function indexAction()
    {
        $accounts = $this->em->getRepository(Account::class)->findAll();
        return ['accounts' => $accounts, 'active_jobs' => $this->jobs->activeByAccount(), 'job_types' => BackgroundJob::TYPES];
    }

    #[Route('/add', name: 'antispam_account_add')]
    #[Template('@Antispam/Account/add.html.twig')]
    public function addAction(Request $request)
    {
        if ($request->getMethod() === 'POST') {
            $this->checkActionToken($request, 'account_form');
            if ($errors = $this->validateForm($request->request->all('account'))) {
                $this->addFlash('danger', implode(' ', $errors));
                return $this->redirectToRoute('antispam_account_add');
            }
            $account = $this->fillAccountFromRequest(new Account(), $request);
            $this->em->persist($account);
            $this->em->flush();
            $this->audit('account.add', targetType: 'account', targetId: $account->getId(), label: $account->getName(), mailbox: $account->getEmail(), details: ['connection_type' => $account->getConnectionType()]);
            return $this->redirectToRoute('antispam_account_index');
        }
        return ['imap_tls' => ImapFlags::defaultOptions(), 'imap_flags' => ImapFlags::DEFAULT_FLAGS, 'oauth_configured' => $this->oauthConfigured()];
    }

    #[Route('/edit/{id}', name: 'antispam_account_edit')]
    #[Template('@Antispam/Account/edit.html.twig')]
    public function editAction($id, Request $request)
    {
        $account = $this->em->getRepository(Account::class)->find($id);
        if (!$account) {
            return $this->redirectToRoute('antispam_account_index');
        }

        if ($request->getMethod() === 'POST') {
            $this->checkActionToken($request, 'account_form');
            if ($errors = $this->validateForm($request->request->all('account'))) {
                $this->addFlash('danger', implode(' ', $errors));
                return $this->redirectToRoute('antispam_account_edit', ['id' => $account->getId()]);
            }
            $pinnedFor = [$account->getSshHost(), (int)$account->getSshPort()];
            $overridesBefore = $account->getSettingsOverrides();
            $account = $this->fillAccountFromRequest($account, $request);
            // A pinned SSH host key belongs to the old host:port.
            if ($pinnedFor !== [$account->getSshHost(), (int)$account->getSshPort()]) {
                $account->setSshHostKey(null);
            }
            $this->em->flush();
            $details = AuditLogger::formFields($request->request->all('account'), ['imap_password', 'plugin_password']);
            // Per-mailbox overrides with their values (no secrets among them).
            $overridesAfter = $account->getSettingsOverrides();
            $details['settings_overrides'] = $overridesAfter;
            $details['settings_changed'] = array_values(array_filter(MailboxSettingsResolver::FIELDS, static fn ($f) => ($overridesBefore[$f] ?? null) !== ($overridesAfter[$f] ?? null)));
            $details['auto_rescan'] = $account->getAutoRescan() ? ['weekday' => $account->getEffectiveRescanWeekday(), 'hour' => $account->getEffectiveRescanHour()] : false;
            $this->audit('account.edit', targetType: 'account', targetId: $account->getId(), label: $account->getName(), mailbox: $account->getEmail(), details: $details);
            return $this->redirectToRoute('antispam_account_index');
        }

        return [
            'global_settings' => $this->mailboxSettings->global(),
            'account' => $account,
            'imap_tls' => ImapFlags::parse($account->getImapFlags()),
            'imap_flags' => $account->getImapFlags() ?: ImapFlags::DEFAULT_FLAGS,
            'oauth_configured' => $this->oauthConfigured(),
            'next_rescan' => $account->getAutoRescan() ? RescanScheduler::nextSlot($account, new \DateTimeImmutable()) : null,
        ];
    }

    /** @return array<string, bool> provider => client id + secret set */
    private function oauthConfigured(): array
    {
        $out = [];
        foreach (OAuthSettings::PROVIDERS as $provider) {
            $out[$provider] = $this->oauthSettings !== null && $this->oauthSettings->isConfigured($provider);
        }
        return $out;
    }

    /**
     * Connection / certificate check run from the account form before saving.
     * `mode=detect` tries 993+SSL/TLS and 143+STARTTLS and suggests settings.
     * With a login the real c-client connection is tried as well; on edit an
     * empty password falls back to the stored one.
     */
    #[Route('/imap-check', name: 'antispam_account_imap_check', methods: ['POST'])]
    public function imapCheckAction(Request $request)
    {
        $this->checkActionToken($request, 'imap_check');
        $data = $request->request->all('account');
        $host = (string)($data['imap_host'] ?? '');

        if ($request->request->get('mode') === 'detect') {
            return new JsonResponse($this->tlsProbe->detect($host));
        }

        $flags = ImapFlags::fromFormData($data);
        $options = ImapFlags::parse($flags);
        $password = (string)($data['imap_password'] ?? '');
        if ($password === '' && !empty($data['id'])) {
            // The stored password is only ever sent to the stored server: a
            // different host typed into the form (or posted by hand) would
            // otherwise receive it in clear text after a TLS-less login.
            [$storedHost, $storedPassword] = $this->storedImapCredentials((string)$data['id']);
            if ($storedPassword !== '' && strcasecmp(trim($host), trim($storedHost)) !== 0) {
                return new JsonResponse(['ok' => false, 'steps' => [[
                    'status' => 'error',
                    'label' => 'Zapisane hasło jest używane tylko z zapisanym serwerem IMAP (' . $storedHost . '). Aby sprawdzić inny serwer, wpisz hasło.',
                ]], 'tls' => null, 'certificate' => null, 'capabilities' => [], 'login' => null, 'flags' => $flags]);
            }
            $password = $storedPassword;
        }

        $result = $this->tlsProbe->probe(
            $host,
            (int)($data['imap_port'] ?? 0),
            $options['encryption'],
            $options['validate_cert'],
            $data['imap_login'] ?? null,
            $password,
            $flags,
        );
        $result['flags'] = $flags;

        return new JsonResponse($result);
    }

    /**
     * Host and decrypted password stored for an account id, or for `legacy`
     * (the single mailbox of Konfiguracja → E-mail).
     *
     * @return array{0: string, 1: string}
     */
    private function storedImapCredentials(string $id): array
    {
        if ($id === 'legacy') {
            return [(string)$this->config->get('imap'), (string)$this->crypto->decrypt((string)$this->config->get('password'))];
        }
        $account = ctype_digit($id) ? $this->em->getRepository(Account::class)->find((int)$id) : null;
        if (!$account) {
            return ['', ''];
        }

        return [(string)$account->getImapHost(), (string)$this->crypto->decrypt($account->getImapPassword())];
    }

    #[Route('/del/{id}', name: 'antispam_account_del', methods: ['POST'])]
    public function delAction($id, Request $request)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        if ($account) {
            $this->em->remove($account);
            $this->em->flush();
            $this->audit('account.delete', targetType: 'account', targetId: $id, label: $account->getName(), mailbox: $account->getEmail(), details: ['connection_type' => $account->getConnectionType()]);
        }
        return $this->redirectToRoute('antispam_account_index');
    }

    #[Route('/test/{id}', name: 'antispam_account_test', methods: ['POST'])]
    #[Template('@Antispam/Account/test.html.twig')]
    public function testAction($id, Request $request)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account) {
            $result['messages'][] = 'Nie znaleziono konta';
            return ['account' => null, 'result' => $result];
        }

        if ($account->isSsh()) {
            $sshService = $this->ssh;
            $result = $sshService->testConnection($account);
        } else {
            try {
                // Password (ext-imap) or OAuth2 XOAUTH2 (socket client), see ImapScanService::connect().
                $connection = $this->imapScan->connect($account, self::TEST_IMAP_OPEN_TIMEOUT, self::TEST_IMAP_READ_TIMEOUT);
                $result['success'] = true;
                $result['messages'][] = $account->isOAuth()
                    ? 'Połączenie IMAP działa (OAuth2, ' . OAuthSettings::LABELS[$account->getOAuthProvider()] . ', użytkownik ' . $account->getOAuthImapUser() . ')'
                    : 'Połączenie IMAP działa';
                $mailboxes = $connection->getMailboxes();
                $result['messages'][] = 'Znalezione foldery: ' . count($mailboxes);
                $connection->close();
            } catch (\Exception $e) {
                $result['messages'][] = 'Błąd: ' . $e->getMessage();
            }
        }

        return ['account' => $account, 'result' => $result];
    }

    #[Route('/deploy/{id}', name: 'antispam_account_deploy', methods: ['POST'])]
    public function deployAction($id, Request $request)
    {
        return $this->queueAccountJob($id, $request, BackgroundJob::TYPE_ACCOUNT_DEPLOY, 'Wdrożenie agenta', true);
    }

    /**
     * Forget the pinned SSH host key; the next connection pins the key the
     * server presents then.
     */
    #[Route('/reset-host-key/{id}', name: 'antispam_account_reset_host_key', methods: ['POST'])]
    public function resetHostKeyAction($id, Request $request)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        if (!$account) {
            return $this->redirectToRoute('antispam_account_index');
        }
        $account->setSshHostKey(null);
        $this->em->flush();
        $this->audit('account.host_key_reset', targetType: 'account', targetId: $id, label: $account->getName(), mailbox: $account->getEmail());
        $this->addFlash('success', 'Zapisany klucz hosta SSH został usunięty. Przy następnym połączeniu zostanie zapamiętany klucz, który przedstawi serwer.');
        return $this->redirectToRoute('antispam_account_edit', ['id' => $account->getId()]);
    }

    #[Route('/sync/{id}', name: 'antispam_account_sync', methods: ['POST'])]
    public function syncAction($id, Request $request)
    {
        return $this->queueAccountJob($id, $request, BackgroundJob::TYPE_ACCOUNT_SYNC, 'Synchronizacja reguł', true);
    }

    /**
     * "Skanuj": queued, never run in the request - a first scan reads the
     * whole INBOX and used to end in a 504 from the proxy. The worker scans
     * big mailboxes in batches (docs/jobs.md).
     */
    #[Route('/scan/{id}', name: 'antispam_account_scan', methods: ['POST'])]
    public function scanAction($id, Request $request)
    {
        return $this->queueAccountJob($id, $request, BackgroundJob::TYPE_ACCOUNT_SCAN, 'Skanowanie');
    }

    /**
     * "Przeskanuj całą skrzynkę ponownie": the whole INBOX against the current
     * rules, in the background, in batches (job account.rescan, one per account
     * while queued / running). Spam is moved, never deleted; kept out of the
     * statistics (docs/spam-handling.md#full-rescan).
     */
    #[Route('/rescan/{id}', name: 'antispam_account_rescan', methods: ['POST'])]
    public function rescanAction($id, Request $request)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        if (!$account || $this->rescans === null) {
            $this->addFlash('danger', 'Nie znaleziono konta');
            return $this->redirectToRoute('antispam_account_index');
        }
        if ($account->isSsh() && !$account->getAgentDeployed()) {
            $this->addFlash('warning', 'Agent nie jest wdrożony na serwerze - najpierw użyj przycisku Wdróż.');
            return $this->redirectToRoute('antispam_account_index');
        }
        $queued = $this->rescans->enqueue($account, RescanScheduler::TRIGGER_PANEL);
        return $this->redirectToJob($queued, 'Ponowny skan całej skrzynki ' . $account->getEmail());
    }

    /** Queue an account job (dedupe: one active job of a type per account) and show its page. */
    private function queueAccountJob($id, Request $request, string $type, string $what, bool $sshOnly = false)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        if (!$account || ($sshOnly && !$account->isSsh())) {
            $this->addFlash('danger', $sshOnly ? 'Nie znaleziono konta lub konto nie jest typu SSH' : 'Nie znaleziono konta');
            return $this->redirectToRoute('antispam_account_index');
        }
        if ($type === BackgroundJob::TYPE_ACCOUNT_SCAN && $account->isSsh() && !$account->getAgentDeployed()) {
            $this->addFlash('warning', 'Agent nie jest wdrożony na serwerze - najpierw użyj przycisku Wdróż.');
            return $this->redirectToRoute('antispam_account_index');
        }
        $queued = $this->jobs->enqueue($type, [], $account,
            label: $what . ': ' . ($account->getName() ?: $account->getEmail()),
            dedupeKey: $type . ':' . $account->getId());
        return $this->redirectToJob($queued, $what . ' ' . $account->getEmail());
    }

    #[Route('/download-agent', name: 'antispam_account_download_agent')]
    public function downloadAgentAction()
    {
        $agentPath = __DIR__ . '/../Resources/agent/antispam-agent.php';
        $response = new BinaryFileResponse($agentPath);
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, 'antispam-agent.php');
        return $response;
    }

    /**
     * Server-side validation of the account form (add / edit). Host names and
     * paths end up in IMAP mailbox strings and remote shell commands, so only
     * plain values are accepted.
     *
     * @return string[] error messages, empty when the data is valid
     */
    public static function validateAccountData(array $data): array
    {
        $errors = [];
        $type = (string)($data['connection_type'] ?? Account::CONNECTION_IMAP);
        if (!in_array($type, [Account::CONNECTION_IMAP, Account::CONNECTION_SSH], true)) {
            return ['Nieznany typ połączenia.'];
        }
        $email = trim((string)($data['email'] ?? ''));
        if ($email === '' || strlen($email) > 255 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Podaj poprawny adres e-mail konta.';
        }
        if (mb_strlen((string)($data['name'] ?? '')) > 255) {
            $errors[] = 'Nazwa jest za długa.';
        }
        $port = static fn ($v, $default) => ($v ?? '') === '' ? $default : (ctype_digit((string)$v) ? (int)$v : -1);
        $isHost = static fn ($h) => strlen($h) <= 253 && preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?$|^\[[0-9A-Fa-f:.]+\]$/', $h);

        if ($type === Account::CONNECTION_IMAP) {
            $method = (string)($data['imap_auth_method'] ?? '');
            $method = $method === '' ? Account::AUTH_PASSWORD : $method;
            if (!in_array($method, Account::AUTH_METHODS, true)) {
                $errors[] = 'Nieznany sposób logowania IMAP.';
            }
            $oauth = $method !== Account::AUTH_PASSWORD;
            $tenant = trim((string)($data['oauth_tenant'] ?? ''));
            if ($tenant !== '' && !OAuthSettings::isValidTenant($tenant)) {
                $errors[] = 'Nieprawidłowy tenant Microsoft (GUID lub domena).';
            }
            if ($oauth && ImapFlags::parse(ImapFlags::fromFormData($data))['encryption'] === ImapFlags::ENCRYPTION_NONE) {
                $errors[] = 'Logowanie OAuth wymaga szyfrowania (SSL/TLS lub STARTTLS).';
            }
            $host = trim((string)($data['imap_host'] ?? ''));
            // OAuth accounts may leave the host empty: the provider's server is used.
            if (($host === '' && !$oauth) || ($host !== '' && !$isHost($host))) {
                $errors[] = 'Nieprawidłowy serwer IMAP (nazwa hosta lub adres IP).';
            }
            $p = $port($data['imap_port'] ?? null, 993);
            if ($p < 1 || $p > 65535) {
                $errors[] = 'Nieprawidłowy port IMAP.';
            }
            if (strlen((string)($data['imap_login'] ?? '')) > 255 || preg_match('/[\x00-\x1f]/', (string)($data['imap_login'] ?? ''))) {
                $errors[] = 'Nieprawidłowy login IMAP.';
            }
            // Custom flags are cleaned by ImapFlags::sanitize().
        } else {
            $host = trim((string)($data['ssh_host'] ?? ''));
            if ($host === '' || !$isHost($host)) {
                $errors[] = 'Nieprawidłowy serwer SSH (nazwa hosta lub adres IP).';
            }
            $p = $port($data['ssh_port'] ?? null, 22);
            if ($p < 1 || $p > 65535) {
                $errors[] = 'Nieprawidłowy port SSH.';
            }
            if (!preg_match('/^[A-Za-z0-9._@-]{1,64}$/', (string)($data['ssh_user'] ?? ''))) {
                $errors[] = 'Nieprawidłowy użytkownik SSH.';
            }
            // SshService shell-escapes the paths; reject only control characters
            // (newlines) and overlong values. The key path is confined to
            // SSH_KEYS_DIR by SshService.
            foreach (['ssh_key_path' => 'Ścieżka klucza SSH', 'maildir_path' => 'Ścieżka Maildir', 'agent_path' => 'Ścieżka agenta'] as $field => $label) {
                $value = (string)($data[$field] ?? '');
                if (strlen($value) > 255 || preg_match('/[\x00-\x1f\x7f]/', $value)) {
                    $errors[] = $label . ': nieprawidłowa wartość.';
                }
            }
        }

        return $errors;
    }

    /**
     * Weekly rescan fields of the account form: day 1-7 and hour 0-23, empty =
     * default (Sunday, 02:00).
     *
     * @return string[] error messages
     */
    public static function validateRescanData(array $data): array
    {
        $errors = [];
        $day = (string)($data['rescan_weekday'] ?? '');
        if ($day !== '' && (!ctype_digit($day) || (int)$day < 1 || (int)$day > 7)) {
            $errors[] = 'Nieprawidłowy dzień cotygodniowego ponownego skanu.';
        }
        $hour = (string)($data['rescan_hour'] ?? '');
        if ($hour !== '' && (!ctype_digit($hour) || (int)$hour > 23)) {
            $errors[] = 'Godzina cotygodniowego ponownego skanu: 0-23.';
        }
        return $errors;
    }

    private function fillAccountFromRequest(Account $account, Request $request)
    {
        $data = $request->request->all('account');

        $account->setAutoRescan(!empty($data['auto_rescan']));
        $account->setRescanWeekday(($data['rescan_weekday'] ?? '') === '' ? null : (int)$data['rescan_weekday']);
        $account->setRescanHour(($data['rescan_hour'] ?? '') === '' ? null : (int)$data['rescan_hour']);

        $account->setName($data['name'] ?? '');
        $account->setEmail($data['email'] ?? '');
        $account->setConnectionType($data['connection_type'] ?? Account::CONNECTION_IMAP);
        $account->setDeleteSpam(!empty($data['delete_spam']));
        // Per-mailbox overrides; empty fields = inherit (validated by validateForm()).
        MailboxSettingsResolver::apply($account, $this->mailboxSettings->parseOverrides($data)[0]);

        // IMAP fields. Changing the login method forgets the stored OAuth tokens.
        $account->setImapAuthMethod((string)($data['imap_auth_method'] ?? Account::AUTH_PASSWORD));
        $account->setOAuthTenant($data['oauth_tenant'] ?? null);
        $host = trim((string)($data['imap_host'] ?? ''));
        if ($host === '' && $account->isOAuth()) {
            $host = OAuthSettings::DEFAULT_IMAP_HOST[$account->getOAuthProvider()];
        }
        $account->setImapHost($host !== '' ? $host : null);
        $account->setImapPort((int)($data['imap_port'] ?? 993));
        $account->setImapLogin($data['imap_login'] ?? null);
        // Stored encrypted; an empty field on edit keeps the current password.
        if (($data['imap_password'] ?? '') !== '') {
            $account->setImapPassword($this->crypto->encrypt($data['imap_password']));
        }
        $account->setImapFlags(ImapFlags::fromFormData($data));

        // SSH fields
        $account->setSshHost($data['ssh_host'] ?? null);
        $account->setSshPort((int)($data['ssh_port'] ?? 22));
        $account->setSshUser($data['ssh_user'] ?? null);
        $account->setSshKeyPath($data['ssh_key_path'] ?? null);
        $account->setMaildirPath($data['maildir_path'] ?? '~/Maildir');
        $account->setAgentPath($data['agent_path'] ?? '~/antispam-agent');

        // Thunderbird plugin password: empty field keeps the current one.
        if (!empty($data['plugin_password_clear'])) {
            $account->setPluginPassword(null);
        } elseif (($data['plugin_password'] ?? '') !== '') {
            $account->setPluginPassword($data['plugin_password']);
        }

        return $account;
    }

    #[Route('/health/{id}', name: 'antispam_account_health', methods: ['POST'])]
    public function healthAction($id, Request $request)
    {
        return $this->queueAccountJob($id, $request, BackgroundJob::TYPE_ACCOUNT_HEALTH, 'Stan agenta', true);
    }
}
