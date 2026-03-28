<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\ScanLog;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;

/**
 * @Route("/account")
 */
class AccountController extends Controller
{
    /**
     * @Route("/index", name="antispam_account_index")
     * @Template
     */
    public function indexAction()
    {
        $em = $this->getDoctrine()->getManager();
        $accounts = $em->getRepository('AntispamBundle:Account')->findAll();
        return ['accounts' => $accounts];
    }

    /**
     * @Route("/add", name="antispam_account_add")
     * @Template
     */
    public function addAction(Request $request)
    {
        if ($request->getMethod() === 'POST') {
            if (!$this->isCsrfTokenValid('account_form', $request->get('_token'))) {
                $this->addFlash('danger', 'Invalid CSRF token');
                return $this->redirectToRoute('antispam_account_add');
            }

            $em = $this->getDoctrine()->getManager();
            $account = $this->fillAccountFromRequest(new Account(), $request);

            $errors = $this->get('validator')->validate($account);
            if (count($errors) > 0) {
                return ['errors' => $errors];
            }

            $em->persist($account);
            $em->flush();
            $this->addFlash('success', 'Account created');
            return $this->redirectToRoute('antispam_account_index');
        }
        return [];
    }

    /**
     * @Route("/edit/{id}", name="antispam_account_edit")
     * @Template
     */
    public function editAction($id, Request $request)
    {
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        if (!$account) {
            return $this->redirectToRoute('antispam_account_index');
        }

        if ($request->getMethod() === 'POST') {
            if (!$this->isCsrfTokenValid('account_form', $request->get('_token'))) {
                $this->addFlash('danger', 'Invalid CSRF token');
                return $this->redirectToRoute('antispam_account_edit', ['id' => $id]);
            }

            $account = $this->fillAccountFromRequest($account, $request);

            $errors = $this->get('validator')->validate($account);
            if (count($errors) > 0) {
                return ['account' => $account, 'errors' => $errors];
            }

            $em->flush();
            $this->addFlash('success', 'Account updated');
            return $this->redirectToRoute('antispam_account_index');
        }

        return ['account' => $account];
    }

    /**
     * @Route("/del/{id}", name="antispam_account_del", methods={"POST"})
     */
    public function delAction($id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_delete_' . $id, $request->get('_token'))) {
            $this->addFlash('danger', 'Invalid CSRF token');
            return $this->redirectToRoute('antispam_account_index');
        }

        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        if ($account) {
            $em->remove($account);
            $em->flush();
            $this->addFlash('success', 'Account deleted');
        }
        return $this->redirectToRoute('antispam_account_index');
    }

    /**
     * @Route("/test/{id}", name="antispam_account_test")
     * @Template
     */
    public function testAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account) {
            $result['messages'][] = 'Account not found';
            return ['account' => null, 'result' => $result];
        }

        if ($account->isSsh()) {
            $sshService = $this->get('antispam.ssh');
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
                $result['messages'][] = 'IMAP connection OK';
                $mailboxes = $connection->getMailboxes();
                $result['messages'][] = 'Mailboxes found: ' . count($mailboxes);
                $connection->close();
            } catch (\Exception $e) {
                $result['messages'][] = 'Error: ' . $e->getMessage();
            }
        }

        return ['account' => $account, 'result' => $result];
    }

    /**
     * @Route("/deploy/{id}", name="antispam_account_deploy")
     * @Template
     */
    public function deployAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account || !$account->isSsh()) {
            $result['messages'][] = 'Account not found or not SSH type';
            return ['account' => $account, 'result' => $result];
        }

        try {
            $deployer = $this->get('antispam.agent.deploy');
            $deployResult = $deployer->deploy($account);
            $account->setAgentDeployed(true);
            $em->flush();
            $result['success'] = true;
            $result['messages'][] = 'Agent deployed successfully';
            $result['deploy_result'] = $deployResult;
        } catch (\Exception $e) {
            $result['messages'][] = 'Deploy failed: ' . $e->getMessage();
        }

        return ['account' => $account, 'result' => $result];
    }

    /**
     * @Route("/sync/{id}", name="antispam_account_sync")
     * @Template
     */
    public function syncAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account || !$account->isSsh()) {
            $result['messages'][] = 'Account not found or not SSH type';
            return ['account' => $account, 'result' => $result];
        }

        try {
            $syncService = $this->get('antispam.agent.sync');
            $counts = $syncService->getRuleCounts($account->getEmail());
            $syncResult = $syncService->sync($account);
            $result['success'] = true;
            $result['messages'][] = 'Rules synced successfully';
            $result['messages'][] = $counts['whitelist'] . ' whitelist, '
                . $counts['email_whitelist'] . ' email whitelist, '
                . $counts['blacklist'] . ' blacklist, '
                . $counts['email_blacklist'] . ' email blacklist';
            $result['sync_result'] = $syncResult;
        } catch (\Exception $e) {
            $result['messages'][] = 'Sync failed: ' . $e->getMessage();
        }

        return ['account' => $account, 'result' => $result];
    }

    /**
     * @Route("/scan/{id}", name="antispam_account_scan")
     * @Template
     */
    public function scanAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account) {
            $result['messages'][] = 'Account not found';
            return ['account' => $account, 'result' => $result];
        }

        try {
            $scanService = $this->get('antispam.agent.scan');

            if ($account->isSsh()) {
                // Auto-sync if needed
                if ($account->getNeedsSync()) {
                    $syncService = $this->get('antispam.agent.sync');
                    $syncService->sync($account);
                    $result['messages'][] = 'Rules auto-synced before scan';
                }
                $scanResult = $scanService->scan($account);
            } else {
                $scanResult = $scanService->scanImap($account);
            }

            $result['success'] = true;
            $result['scan_result'] = $scanResult;
        } catch (\Exception $e) {
            $result['messages'][] = 'Scan failed: ' . $e->getMessage();
        }

        return ['account' => $account, 'result' => $result];
    }

    /**
     * @Route("/history/{id}", name="antispam_account_history")
     * @Template
     */
    public function historyAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);

        if (!$account) {
            return $this->redirectToRoute('antispam_account_index');
        }

        $logs = $em->getRepository('AntispamBundle:ScanLog')->findBy(
            ['account' => $account],
            ['scannedAt' => 'DESC'],
            50
        );

        return ['account' => $account, 'logs' => $logs];
    }

    /**
     * @Route("/download-agent", name="antispam_account_download_agent")
     */
    public function downloadAgentAction()
    {
        $agentPath = __DIR__ . '/../Resources/agent/antispam-agent.php';
        $response = new BinaryFileResponse($agentPath);
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, 'antispam-agent.php');
        return $response;
    }

    private function fillAccountFromRequest(Account $account, Request $request)
    {
        $data = $request->get('account');
        $keyEncryption = $this->get('antispam.key_encryption');

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

        // Handle SSH private key (encrypt before storing)
        $keyContent = $data['ssh_key_private'] ?? '';
        if (!empty($keyContent)) {
            $account->setSshKeyPrivate($keyEncryption->encrypt($keyContent));
        }

        // Handle passphrase (encrypt before storing)
        $passphrase = $data['ssh_key_passphrase'] ?? '';
        if (!empty($passphrase)) {
            $account->setSshKeyPassphrase($keyEncryption->encrypt($passphrase));
        } elseif (isset($data['ssh_key_passphrase'])) {
            $account->setSshKeyPassphrase(null);
        }

        return $account;
    }
}
