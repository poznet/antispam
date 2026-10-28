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
    private const SCORELOG_PER_PAGE = 50;
    private const DECISIONS = [
        SpamScoreLog::DECISION_HAM,
        SpamScoreLog::DECISION_QUARANTINE,
        SpamScoreLog::DECISION_SPAM,
        SpamScoreLog::DECISION_WHITELISTED,
    ];

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

        return ['mailboxes' => $mailboxes, 'logs' => $logs, 'locations' => self::locateLogs($logs, $mailboxes)];
    }

    /**
     * Where each logged quarantine decision's message is now, judged from the
     * recorded source/outcome and whether a matching message (same account,
     * sender and subject) is listed in that account's quarantine right now.
     *
     * @param SpamScoreLog[] $logs
     *
     * @return array log id => ['label' => string, 'class' => bootstrap label suffix]
     */
    public static function locateLogs(array $logs, array $mailboxes)
    {
        $present = [];
        foreach ($mailboxes as $mailbox) {
            foreach ($mailbox['items'] as $item) {
                $present[self::matchKey($mailbox['account_email'], $item['from'], $item['subject'])] = true;
            }
        }

        $out = [];
        foreach ($logs as $log) {
            $isPlugin = $log->getSource() === SpamScoreLog::SOURCE_PLUGIN;
            if ($log->getSource() === null) {
                // Older entries: the plugin marked itself with a pseudo-reason.
                foreach ($log->getReasonsDecoded() as $r) {
                    $isPlugin = $isPlugin || str_starts_with((string)($r['rule'] ?? ''), 'source:');
                }
            }

            if (isset($present[self::matchKey($log->getAccountEmail(), $log->getSender(), $log->getSubject())])) {
                $out[$log->getId()] = ['label' => 'w kwarantannie', 'class' => 'warning'];
            } elseif ($isPlugin) {
                $out[$log->getId()] = ['label' => 'ocena wtyczki - na serwerze nic nie przeniesiono', 'class' => 'default'];
            } elseif ($log->getOutcome() === SpamScoreLog::OUTCOME_MOVE_FAILED) {
                $out[$log->getId()] = ['label' => 'przeniesienie nie powiodło się - została w INBOX', 'class' => 'danger'];
            } elseif ($log->getOutcome() === SpamScoreLog::OUTCOME_QUARANTINED) {
                $out[$log->getId()] = ['label' => 'już nie w kwarantannie (dostarczona lub usunięta)', 'class' => 'success'];
            } else {
                $out[$log->getId()] = ['label' => 'brak w kwarantannie (wpis sprzed zapisywania wyniku)', 'class' => 'default'];
            }
        }
        return $out;
    }

    private static function matchKey($account, $sender, $subject)
    {
        // SpamScoreLog keeps at most 500 bytes of the subject.
        return strtolower(trim((string)$account)) . '|' . strtolower(trim((string)$sender)) . '|' . substr(trim((string)$subject), 0, 500);
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
    public function scorelogAction(Request $request)
    {
        $repo = $this->em->getRepository(SpamScoreLog::class);
        $filters = $this->scorelogFilters($request);
        $page = max(1, $request->query->getInt('page', 1));

        $result = $repo->search($filters, $page, self::SCORELOG_PER_PAGE);
        $pages = max(1, (int)ceil($result['total'] / self::SCORELOG_PER_PAGE));

        // Query params of the active filter (without page) - reused by pagination and the decision tiles.
        $query = array_filter([
            'decision' => $filters['decision'],
            'account' => $filters['account'],
            'q' => $filters['q'],
            'from' => $filters['from']?->format('Y-m-d'),
            'to' => $filters['to']?->format('Y-m-d'),
            'min_score' => $filters['minScore'],
        ], fn($v) => $v !== null && $v !== '');

        return [
            'logs' => $result['items'],
            'total' => $result['total'],
            'page' => min($page, $pages),
            'pages' => $pages,
            'filters' => $filters,
            'query' => $query,
            'accounts' => $repo->distinctAccounts(),
            'stats' => $repo->statsByDecision(new \DateTime('-30 days')),
        ];
    }

    /** Parse and validate the score log filter from the query string; invalid values are ignored. */
    private function scorelogFilters(Request $request): array
    {
        $q = $request->query;
        $decision = (string)$q->get('decision', '');
        $date = function (string $key) use ($q): ?\DateTime {
            $value = (string)$q->get($key, '');
            $dt = $value !== '' ? \DateTime::createFromFormat('!Y-m-d', $value) : false;
            // Reject overflowing dates like 2026-13-45 that createFromFormat silently rolls over.
            return $dt && $dt->format('Y-m-d') === $value ? $dt : null;
        };
        $minScore = (string)$q->get('min_score', '');

        return [
            'decision' => in_array($decision, self::DECISIONS, true) ? $decision : null,
            'account' => trim((string)$q->get('account', '')) ?: null,
            'q' => trim((string)$q->get('q', '')),
            'from' => $date('from'),
            'to' => $date('to'),
            'minScore' => preg_match('/^-?\d+$/', $minScore) ? (int)$minScore : null,
        ];
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
