<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\PluginReport;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\QuarantineDigestService;
use AntispamBundle\Services\QuarantineService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/spambox')]
class SpamboxController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private InboxService $inbox,
        private ConnectionService $connection,
        private QuarantineService $quarantine,
    ) {
    }

    #[Route('/index', name: 'antispam_spambox_index')]
    #[Template('@Antispam/Spambox/index.html.twig')]
    public function indexAction()
    {
        return ['messages' => $this->loadFolder($this->inbox->getSpamFolderName())];
    }

    /**
     * Quarantine of every mailbox: the legacy IMAP QUARANTINE folder and the
     * Maildir quarantine of each SSH account with a deployed agent. The
     * dashboard counts quarantine decisions from the score log, so those are
     * listed too - a decision can outlive its message (released, deleted, or
     * a Thunderbird plugin check that never moves anything on the server).
     */
    #[Route('/quarantine', name: 'antispam_spambox_quarantine', methods: ['GET'])]
    #[Template('@Antispam/Spambox/quarantine.html.twig')]
    public function quarantineAction()
    {
        $mailboxes = [];
        foreach ($this->quarantine->getMailboxes() as $mailbox) {
            $items = [];
            $error = null;
            try {
                foreach ($this->quarantine->listItems($mailbox['key'], null, 100) as $item) {
                    $item['labels'] = QuarantineDigestService::reasonLabels($item['reasons']);
                    $item['high_risk'] = QuarantineDigestService::isHighRisk($item['reasons']);
                    $items[] = $item;
                }
            } catch (\Throwable $e) {
                $error = $e->getMessage();
            }
            $mailboxes[] = $mailbox + ['items' => $items, 'error' => $error];
        }

        $logs = $this->em->getRepository(SpamScoreLog::class)
            ->findRecentByDecision(SpamScoreLog::DECISION_QUARANTINE, new \DateTime('-30 days'), 50);

        return ['mailboxes' => $mailboxes, 'logs' => $logs];
    }

    /** Release (optionally whitelisting the sender) or delete a quarantined message. */
    #[Route('/quarantine/action', name: 'antispam_spambox_quarantine_action', methods: ['POST'])]
    public function quarantineItemAction(Request $request)
    {
        if (!$this->isCsrfTokenValid('quarantine_action', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            return $this->redirectToRoute('antispam_spambox_quarantine');
        }

        $key = (string)$request->request->get('mailbox');
        $id = (string)$request->request->get('id');
        $action = (string)$request->request->get('action');

        try {
            $result = match ($action) {
                'release' => $this->quarantine->release($key, $id),
                'whitelist' => $this->quarantine->release($key, $id, true),
                'delete' => $this->quarantine->delete($key, $id),
                default => ['success' => false, 'message' => 'Nieznana akcja'],
            };
        } catch (\Throwable $e) {
            $result = ['success' => false, 'message' => 'Operacja nie powiodła się: ' . $e->getMessage()];
        }

        $this->addFlash($result['success'] ? 'success' : 'danger', $result['message']);
        return $this->redirectToRoute('antispam_spambox_quarantine');
    }

    /** Move a message from SPAM or QUARANTINE back to INBOX. */
    #[Route('/restore/{folder}/{id}', name: 'antispam_spambox_restore')]
    public function restoreAction($folder, $id)
    {
        $allowed = [
            $this->inbox->getSpamFolderName(),
            $this->inbox->getQuarantineFolderName(),
        ];
        if (!in_array($folder, $allowed, true)) {
            $this->addFlash('danger', 'Nieprawidłowy folder');
            return $this->redirectToRoute('antispam_spambox_index');
        }

        try {
            $messages = $this->inbox->getInbox($folder);
            $msg = $this->inbox->getMessage((int)$id);
            $inboxMailbox = $this->connection->getConnection()->getMailbox('INBOX');
            $msg->move($inboxMailbox);
            $this->inbox->expunge();
            $this->addFlash('success', 'Wiadomość przywrócona do INBOX');
        } catch (\Throwable $e) {
            $this->addFlash('danger', 'Przywracanie nie powiodło się: ' . $e->getMessage());
        }

        return $this->redirectToRoute($folder === 'QUARANTINE'
            ? 'antispam_spambox_quarantine'
            : 'antispam_spambox_index');
    }

    /** Recent score log with reasons - "why did X get flagged". */
    #[Route('/scorelog', name: 'antispam_spambox_scorelog')]
    #[Template('@Antispam/Spambox/scorelog.html.twig')]
    public function scorelogAction()
    {
        $logs = $this->em->getRepository(SpamScoreLog::class)->findRecent(100);
        $stats = $this->em->getRepository(SpamScoreLog::class)->statsByDecision(new \DateTime('-30 days'));
        return ['logs' => $logs, 'stats' => $stats];
    }

    /** Spam / not-spam reports from the Thunderbird plugin, anonymous ones included. */
    #[Route('/plugin-reports', name: 'antispam_spambox_pluginreports')]
    #[Template('@Antispam/Spambox/pluginReports.html.twig')]
    public function pluginReportsAction(Request $request)
    {
        $verdict = in_array($request->query->get('verdict'), ['spam', 'ham'], true) ? $request->query->get('verdict') : null;
        $who = in_array($request->query->get('who'), ['anonymous', 'account'], true) ? $request->query->get('who') : null;
        $repo = $this->em->getRepository(PluginReport::class);
        $since = new \DateTime('-30 days');

        return [
            'reports' => $repo->findRecent(200, $verdict, $who),
            'stats' => $repo->stats($since),
            'top' => $repo->topSenders($since),
            'verdict' => $verdict,
            'who' => $who,
        ];
    }

    private function loadFolder($folderName)
    {
        $messages = [];
        try {
            $list = $this->inbox->getInbox($folderName);
        } catch (\Throwable $e) {
            return $messages;
        }

        $count = 0;
        foreach ($list as $m) {
            if ($count++ >= 20) break;
            try {
                $msg = $this->inbox->getMessage($m->getNumber());
                $from = $msg->getFrom();
                $messages[] = [
                    'subject' => (string)$msg->getSubject(),
                    'from' => $from ? $from->getFullAddress() : '',
                    'content' => $msg->getBodyHtml(),
                    'date' => $msg->getDate(),
                    'id' => $msg->getNumber(),
                ];
            } catch (\Throwable $e) {
                continue;
            }
        }
        return $messages;
    }
}
