<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\InboxService;
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
    ) {
    }

    #[Route('/index', name: 'antispam_spambox_index')]
    #[Template('@Antispam/Spambox/index.html.twig')]
    public function indexAction()
    {
        return ['messages' => $this->loadFolder($this->inbox->getSpamFolderName())];
    }

    #[Route('/quarantine', name: 'antispam_spambox_quarantine')]
    #[Template('@Antispam/Spambox/quarantine.html.twig')]
    public function quarantineAction()
    {
        return ['messages' => $this->loadFolder($this->inbox->getQuarantineFolderName())];
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
