<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\ImapFlags;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\ImapTlsProbe;
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

#[Route('/account')]
class AccountController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private SshService $ssh,
        private AgentRulesExporter $rulesExporter,
        private ImapScanService $imapScan,
        private CryptoService $crypto,
        private ImapTlsProbe $tlsProbe,
        private ConfigService $config,
    ) {
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
        return ['accounts' => $accounts];
    }

    #[Route('/add', name: 'antispam_account_add')]
    #[Template('@Antispam/Account/add.html.twig')]
    public function addAction(Request $request)
    {
        if ($request->getMethod() === 'POST') {
            $this->checkActionToken($request, 'account_form');
            if ($errors = self::validateAccountData($request->request->all('account'))) {
                $this->addFlash('danger', implode(' ', $errors));
                return $this->redirectToRoute('antispam_account_add');
            }
            $account = $this->fillAccountFromRequest(new Account(), $request);
            $this->em->persist($account);
            $this->em->flush();
            return $this->redirectToRoute('antispam_account_index');
        }
        return ['imap_tls' => ImapFlags::defaultOptions(), 'imap_flags' => ImapFlags::DEFAULT_FLAGS];
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
            if ($errors = self::validateAccountData($request->request->all('account'))) {
                $this->addFlash('danger', implode(' ', $errors));
                return $this->redirectToRoute('antispam_account_edit', ['id' => $account->getId()]);
            }
            $account = $this->fillAccountFromRequest($account, $request);
            $this->em->flush();
            return $this->redirectToRoute('antispam_account_index');
        }

        return [
            'account' => $account,
            'imap_tls' => ImapFlags::parse($account->getImapFlags()),
            'imap_flags' => $account->getImapFlags() ?: ImapFlags::DEFAULT_FLAGS,
        ];
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
                $server = new \Ddeboer\Imap\Server(
                    $account->getImapHost(),
                    $account->getImapPort(),
                    $account->getImapFlags()
                );
                $connection = $server->authenticate($account->getImapLogin(), (string)$this->crypto->decrypt($account->getImapPassword()));
                $result['success'] = true;
                $result['messages'][] = 'Połączenie IMAP działa';
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
    #[Template('@Antispam/Account/deploy.html.twig')]
    public function deployAction($id, Request $request)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account || !$account->isSsh()) {
            $result['messages'][] = 'Nie znaleziono konta lub konto nie jest typu SSH';
            return ['account' => $account, 'result' => $result];
        }

        try {
            $sshService = $this->ssh;
            $deployResult = $sshService->deployAgent($account);
            $account->setAgentDeployed(true);
            $this->em->flush();
            $result['success'] = true;
            $result['messages'][] = 'Agent został wdrożony';
            $result['deploy_result'] = $deployResult;
        } catch (\Exception $e) {
            $result['messages'][] = 'Wdrożenie nie powiodło się: ' . $e->getMessage();
        }

        return ['account' => $account, 'result' => $result];
    }

    #[Route('/sync/{id}', name: 'antispam_account_sync', methods: ['POST'])]
    #[Template('@Antispam/Account/sync.html.twig')]
    public function syncAction($id, Request $request)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account || !$account->isSsh()) {
            $result['messages'][] = 'Nie znaleziono konta lub konto nie jest typu SSH';
            return ['account' => $account, 'result' => $result];
        }

        try {
            $rules = $this->rulesExporter->export($account->getEmail());
            $sshService = $this->ssh;
            $syncResult = $sshService->syncRules($account, json_encode($rules));
            $result['success'] = true;
            $result['messages'][] = 'Reguły zostały zsynchronizowane';
            $result['sync_result'] = $syncResult;
        } catch (\Exception $e) {
            $result['messages'][] = 'Synchronizacja nie powiodła się: ' . $e->getMessage();
        }

        return ['account' => $account, 'result' => $result];
    }

    #[Route('/scan/{id}', name: 'antispam_account_scan', methods: ['POST'])]
    #[Template('@Antispam/Account/scan.html.twig')]
    public function scanAction($id, Request $request)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account) {
            $result['messages'][] = 'Nie znaleziono konta';
            return ['account' => $account, 'result' => $result];
        }

        try {
            if ($account->isSsh()) {
                $sshService = $this->ssh;
                $scanResult = $sshService->runScan($account);
            } else {
                $scanResult = $this->imapScan->scanAccount($account);
            }

            $account->markScanned($scanResult);
            $this->em->flush();

            $result['success'] = true;
            $result['scan_result'] = $scanResult;
        } catch (\Exception $e) {
            $result['messages'][] = 'Skanowanie nie powiodło się: ' . $e->getMessage();
        }

        return ['account' => $account, 'result' => $result];
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
            $host = trim((string)($data['imap_host'] ?? ''));
            if ($host === '' || !$isHost($host)) {
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

    private function fillAccountFromRequest(Account $account, Request $request)
    {
        $data = $request->request->all('account');

        $account->setName($data['name'] ?? '');
        $account->setEmail($data['email'] ?? '');
        $account->setConnectionType($data['connection_type'] ?? Account::CONNECTION_IMAP);
        $account->setDeleteSpam(!empty($data['delete_spam']));

        // IMAP fields
        $account->setImapHost($data['imap_host'] ?? null);
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
    #[Template('@Antispam/Account/health.html.twig')]
    public function healthAction($id, Request $request)
    {
        $this->checkActionToken($request, 'account_action_' . $id);
        $account = $this->em->getRepository(Account::class)->find($id);
        $result = ['success' => false, 'messages' => []];
        if (!$account || !$account->isSsh()) {
            $result['messages'][] = 'Nie znaleziono konta lub konto nie jest typu SSH';
            return ['account' => $account, 'result' => $result];
        }
        try {
            $health = $this->ssh->runHealth($account);
            $result['success'] = true;
            $result['health'] = $health;
        } catch (\Exception $e) {
            $result['messages'][] = 'Sprawdzenie stanu agenta nie powiodło się: ' . $e->getMessage();
        }
        return ['account' => $account, 'result' => $result];
    }
}
