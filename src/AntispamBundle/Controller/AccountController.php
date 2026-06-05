<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\SshService;
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
            if (!$this->isCsrfTokenValid('account_form', $request->request->get('_token'))) {
                throw $this->createAccessDeniedException('Invalid CSRF token');
            }
            $em = $this->getDoctrine()->getManager();
            $account = $this->fillAccountFromRequest(new Account(), $request);
            $em->persist($account);
            $em->flush();
            return $this->redirectToRoute('antispam_account_index');
        }
        return [];
    }

    /**
     * @Route("/edit/{id}", name="antispam_account_edit", requirements={"id"="\d+"})
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
            if (!$this->isCsrfTokenValid('account_form', $request->request->get('_token'))) {
                throw $this->createAccessDeniedException('Invalid CSRF token');
            }
            $account = $this->fillAccountFromRequest($account, $request);
            $em->flush();
            return $this->redirectToRoute('antispam_account_index');
        }

        return ['account' => $account];
    }

    /**
     * @Route("/del/{id}", name="antispam_account_del", methods={"POST"}, requirements={"id"="\d+"})
     */
    public function delAction($id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_del_' . $id, $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        if ($account) {
            $em->remove($account);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_account_index');
    }

    /**
     * @Route("/test/{id}", name="antispam_account_test", methods={"POST"}, requirements={"id"="\d+"})
     * @Template
     */
    public function testAction($id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_action_' . $id, $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }
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
                $connection = $server->authenticate(
                    $account->getImapLogin(),
                    $this->get('antispam.crypto')->decrypt($account->getImapPassword())
                );
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
     * @Route("/deploy/{id}", name="antispam_account_deploy", methods={"POST"}, requirements={"id"="\d+"})
     * @Template
     */
    public function deployAction($id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_action_' . $id, $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account || !$account->isSsh()) {
            $result['messages'][] = 'Account not found or not SSH type';
            return ['account' => $account, 'result' => $result];
        }

        try {
            $sshService = $this->get('antispam.ssh');
            $deployResult = $sshService->deployAgent($account);
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
     * @Route("/sync/{id}", name="antispam_account_sync", methods={"POST"}, requirements={"id"="\d+"})
     * @Template
     */
    public function syncAction($id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_action_' . $id, $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account || !$account->isSsh()) {
            $result['messages'][] = 'Account not found or not SSH type';
            return ['account' => $account, 'result' => $result];
        }

        try {
            $rules = $this->exportRules($em, $account->getEmail());
            $sshService = $this->get('antispam.ssh');
            $syncResult = $sshService->syncRules($account, json_encode($rules));
            $result['success'] = true;
            $result['messages'][] = 'Rules synced successfully';
            $result['sync_result'] = $syncResult;
        } catch (\Exception $e) {
            $result['messages'][] = 'Sync failed: ' . $e->getMessage();
        }

        return ['account' => $account, 'result' => $result];
    }

    /**
     * @Route("/scan/{id}", name="antispam_account_scan", methods={"POST"}, requirements={"id"="\d+"})
     * @Template
     */
    public function scanAction($id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_action_' . $id, $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        $result = ['success' => false, 'messages' => []];

        if (!$account) {
            $result['messages'][] = 'Account not found';
            return ['account' => $account, 'result' => $result];
        }

        try {
            if ($account->isSsh()) {
                $sshService = $this->get('antispam.ssh');
                $scanResult = $sshService->runScan($account);
            } else {
                $scanResult = $this->runImapScan($account);
            }

            $account->setLastScanAt(new \DateTime());
            $account->setLastScanResult(json_encode($scanResult));
            $em->flush();

            $result['success'] = true;
            $result['scan_result'] = $scanResult;
        } catch (\Exception $e) {
            $result['messages'][] = 'Scan failed: ' . $e->getMessage();
        }

        return ['account' => $account, 'result' => $result];
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
        $crypto = $this->get('antispam.crypto');

        $account->setName($data['name'] ?? '');
        $account->setEmail($data['email'] ?? '');
        $account->setConnectionType($data['connection_type'] ?? Account::CONNECTION_IMAP);
        $account->setDeleteSpam(!empty($data['delete_spam']));

        // IMAP fields
        $account->setImapHost($data['imap_host'] ?? null);
        $account->setImapPort((int)($data['imap_port'] ?? 993));
        $account->setImapLogin($data['imap_login'] ?? null);
        // Only re-encrypt when the operator typed a new password; an empty
        // field on the edit form means "keep the stored one".
        $newPassword = $data['imap_password'] ?? null;
        if ($newPassword !== null && $newPassword !== '') {
            $account->setImapPassword($crypto->encrypt($newPassword));
        }
        $account->setImapFlags($data['imap_flags'] ?? '/imap/ssl');

        // SSH fields
        $account->setSshHost($data['ssh_host'] ?? null);
        $account->setSshPort((int)($data['ssh_port'] ?? 22));
        $account->setSshUser($data['ssh_user'] ?? null);
        $account->setSshKeyPath($data['ssh_key_path'] ?? null);
        $account->setMaildirPath($data['maildir_path'] ?? '~/Maildir');
        $account->setAgentPath($data['agent_path'] ?? '~/antispam-agent');

        return $account;
    }

    private function exportRules($em, $email)
    {
        $rules = [
            'whitelist' => [],
            'email_whitelist' => [],
            'blacklist' => [],
            'email_blacklist' => [],
            'dnsbl' => [],
        ];

        foreach ($em->getRepository('AntispamBundle:Whitelist')->findBy(['email' => $email]) as $item) {
            $rules['whitelist'][] = [
                'email' => $item->getEmail(),
                'host' => $item->getHost(),
                'pattern_type' => $item->getPatternType(),
            ];
        }
        foreach ($em->getRepository('AntispamBundle:EmailWhitelist')->findBy(['email' => $email]) as $item) {
            $rules['email_whitelist'][] = [
                'email' => $item->getEmail(),
                'whitelistemail' => $item->getWhitelistemail(),
                'pattern_type' => $item->getPatternType(),
            ];
        }
        foreach ($em->getRepository('AntispamBundle:Blacklist')->findBy(['email' => $email]) as $item) {
            $rules['blacklist'][] = [
                'email' => $item->getEmail(),
                'host' => $item->getHost(),
                'pattern_type' => $item->getPatternType(),
                'score' => $item->getScore(),
            ];
        }
        foreach ($em->getRepository('AntispamBundle:EmailBlacklist')->findBy(['email' => $email]) as $item) {
            $rules['email_blacklist'][] = [
                'email' => $item->getEmail(),
                'blacklistemail' => $item->getBlacklistemail(),
                'pattern_type' => $item->getPatternType(),
                'score' => $item->getScore(),
            ];
        }
        foreach ($em->getRepository('AntispamBundle:DnsblProvider')->findAll() as $prov) {
            $rules['dnsbl'][] = [
                'name' => $prov->getName(),
                'zone' => $prov->getZone(),
                'score' => $prov->getScore(),
                'enabled' => $prov->isEnabled(),
                'cache_ttl' => $prov->getCacheTtl(),
            ];
        }

        $rules['settings'] = $this->get('antispam.scoring')->exportAgentSettings();

        return $rules;
    }

    /**
     * @Route("/health/{id}", name="antispam_account_health", methods={"POST"}, requirements={"id"="\d+"})
     * @Template
     */
    public function healthAction($id, Request $request)
    {
        if (!$this->isCsrfTokenValid('account_action_' . $id, $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }
        $em = $this->getDoctrine()->getManager();
        $account = $em->getRepository('AntispamBundle:Account')->find($id);
        $result = ['success' => false, 'messages' => []];
        if (!$account || !$account->isSsh()) {
            $result['messages'][] = 'Account not found or not SSH type';
            return ['account' => $account, 'result' => $result];
        }
        try {
            $health = $this->get('antispam.ssh')->runHealth($account);
            $result['success'] = true;
            $result['health'] = $health;
        } catch (\Exception $e) {
            $result['messages'][] = 'Health check failed: ' . $e->getMessage();
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
        $connection = $server->authenticate(
            $account->getImapLogin(),
            $this->get('antispam.crypto')->decrypt($account->getImapPassword())
        );
        $inbox = $connection->getMailbox('INBOX');
        $messages = $inbox->getMessages();

        $dispatcher = $this->get('event_dispatcher');
        $stats = ['total' => 0, 'checked' => 0, 'whitelisted' => 0, 'blacklisted' => 0,
                  'quarantined' => 0, 'moved_to_spam' => 0];

        foreach ($messages as $msg) {
            $stats['total']++;
            try {
                $event = new \AntispamBundle\Event\MessageEvent($msg, $account->getEmail());
                $dispatcher->dispatch('antispam.check.message', $event);

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

        $connection->close();
        return $stats;
    }
}
