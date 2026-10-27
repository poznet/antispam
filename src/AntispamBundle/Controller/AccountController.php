<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

#[Route('/account')]
class AccountController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private SshService $ssh,
        private AgentRulesExporter $rulesExporter,
        private EventDispatcherInterface $dispatcher,
    ) {
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
                $account = $this->fillAccountFromRequest(new Account(), $request);
            $this->em->persist($account);
            $this->em->flush();
            return $this->redirectToRoute('antispam_account_index');
        }
        return [];
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
            $account = $this->fillAccountFromRequest($account, $request);
            $this->em->flush();
            return $this->redirectToRoute('antispam_account_index');
        }

        return ['account' => $account];
    }

    #[Route('/del/{id}', name: 'antispam_account_del')]
    public function delAction($id)
    {
        $account = $this->em->getRepository(Account::class)->find($id);
        if ($account) {
            $this->em->remove($account);
            $this->em->flush();
        }
        return $this->redirectToRoute('antispam_account_index');
    }

    #[Route('/test/{id}', name: 'antispam_account_test')]
    #[Template('@Antispam/Account/test.html.twig')]
    public function testAction($id)
    {
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
                $connection = $server->authenticate($account->getImapLogin(), $account->getImapPassword());
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

    #[Route('/deploy/{id}', name: 'antispam_account_deploy')]
    #[Template('@Antispam/Account/deploy.html.twig')]
    public function deployAction($id)
    {
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

    #[Route('/sync/{id}', name: 'antispam_account_sync')]
    #[Template('@Antispam/Account/sync.html.twig')]
    public function syncAction($id)
    {
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

    #[Route('/scan/{id}', name: 'antispam_account_scan')]
    #[Template('@Antispam/Account/scan.html.twig')]
    public function scanAction($id)
    {
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
                $scanResult = $this->runImapScan($account);
            }

            $account->setLastScanAt(new \DateTime());
            $account->setLastScanResult(json_encode($scanResult));
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

    private function fillAccountFromRequest(Account $account, Request $request)
    {
        $data = $request->request->all('account');

        $account->setName($data['name'] ?? '');
        $account->setEmail($data['email'] ?? '');
        $account->setConnectionType($data['connection_type'] ?? Account::CONNECTION_IMAP);
        $account->setDeleteSpam(!empty($data['delete_spam']));

        // IMAP fields
        $account->setImapHost($data['imap_host'] ?? null);
        $account->setImapPort((int)($data['imap_port'] ?? 143));
        $account->setImapLogin($data['imap_login'] ?? null);
        $account->setImapPassword($data['imap_password'] ?? null);
        $account->setImapFlags($data['imap_flags'] ?? '/novalidate-cert/notls');

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

    #[Route('/health/{id}', name: 'antispam_account_health')]
    #[Template('@Antispam/Account/health.html.twig')]
    public function healthAction($id)
    {
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

    private function runImapScan(Account $account)
    {
        $server = new \Ddeboer\Imap\Server(
            $account->getImapHost(),
            $account->getImapPort(),
            $account->getImapFlags()
        );
        $connection = $server->authenticate($account->getImapLogin(), $account->getImapPassword());
        $inbox = $connection->getMailbox('INBOX');
        $messages = $inbox->getMessages();

        $stats = ['total' => 0, 'checked' => 0, 'whitelisted' => 0, 'blacklisted' => 0,
                  'quarantined' => 0, 'moved_to_spam' => 0];

        foreach ($messages as $msg) {
            $stats['total']++;
            try {
                $event = new \AntispamBundle\Event\MessageEvent($msg, $account->getEmail());
                $this->dispatcher->dispatch($event, 'antispam.check.message');

                if ($event->isCheckedbefore()) { continue; }
                $stats['checked']++;
                if ($event->isWhitelist()) { $stats['whitelisted']++; }
                if ($event->isSpam()) {
                    $stats['blacklisted']++;
                    if ($event->isDelete()) { $stats['moved_to_spam']++; }
                }
            } catch (\Exception $e) {
                // Skip messages with encoding issues
            }
        }

        $connection->expunge();
        $connection->close();
        return $stats;
    }
}
