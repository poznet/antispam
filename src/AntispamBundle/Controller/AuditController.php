<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\ConfigService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * "Dziennik audytu": who did what and when (see docs/audit.md). Administrators
 * only - the catch-all access_control rule covers /audit, IsGranted repeats it
 * so a future access_control change cannot expose the log to ROLE_USER.
 */
#[Route('/audit')]
#[IsGranted('ROLE_ADMIN')]
class AuditController extends AbstractController
{
    const PER_PAGE = 50;
    /** Upper bound of one CSV export (newest rows of the filter). */
    const EXPORT_LIMIT = 50000;

    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
    ) {
    }

    #[Route('', name: 'antispam_audit_index', methods: ['GET'])]
    #[Template('@Antispam/Audit/index.html.twig')]
    public function indexAction(Request $request)
    {
        $repo = $this->em->getRepository(AuditLog::class);
        $filters = self::filters($request);
        $page = max(1, $request->query->getInt('page', 1));
        $result = $repo->search($filters, $page, self::PER_PAGE);
        $pages = max(1, (int)ceil($result['total'] / self::PER_PAGE));

        $retention = $this->config->get(AuditLogger::CONFIG_RETENTION);

        return [
            'entries' => $result['items'],
            'total' => $result['total'],
            'page' => min($page, $pages),
            'pages' => $pages,
            'filters' => $filters,
            'query' => self::query($filters),
            'actions' => AuditLogger::ACTIONS + array_fill_keys(array_diff($repo->distinctActions(), array_keys(AuditLogger::ACTIONS)), null),
            'action_groups' => self::actionGroups(),
            'actor_types' => AuditLog::ACTOR_TYPES,
            'retention' => $retention === null || $retention === '' || !is_numeric($retention) ? AuditLogger::DEFAULT_RETENTION_DAYS : max(0, (int)$retention),
        ];
    }

    /** Same filters as the list, as CSV (UTF-8 with BOM, `;` separated - opens in Excel). */
    #[Route('/export.csv', name: 'antispam_audit_export', methods: ['GET'])]
    public function exportAction(Request $request)
    {
        $filters = self::filters($request);
        $rows = $this->em->getRepository(AuditLog::class)->export($filters, self::EXPORT_LIMIT);

        $response = new StreamedResponse(function () use ($rows) {
            $out = fopen('php://output', 'w');
            fwrite($out, "\xEF\xBB\xBF");
            fputcsv($out, ['czas', 'aktor', 'typ aktora', 'rola', 'IP', 'akcja', 'typ celu', 'id celu', 'cel', 'skrzynka', 'szczegóły'], ';', '"', '');
            foreach ($rows as $e) {
                /** @var AuditLog $e */
                fputcsv($out, array_map([self::class, 'csvCell'], [
                    $e->getCreatedAt()->format('Y-m-d H:i:s'),
                    $e->getActor(),
                    $e->getActorType(),
                    $e->getRole(),
                    $e->getIp(),
                    $e->getAction(),
                    $e->getTargetType(),
                    $e->getTargetId(),
                    $e->getTargetLabel(),
                    $e->getMailbox(),
                    $e->getDetails(),
                ]), ';', '"', '');
                $this->em->detach($e);
            }
            fclose($out);
        });
        $response->headers->set('Content-Type', 'text/csv; charset=utf-8');
        $response->headers->set('Cache-Control', 'private, no-store');
        $response->headers->set('Content-Disposition', $response->headers->makeDisposition(
            ResponseHeaderBag::DISPOSITION_ATTACHMENT,
            'dziennik-audytu-' . date('Y-m-d') . '.csv'
        ));
        return $response;
    }

    /**
     * A cell a spreadsheet will not evaluate: values starting with = + - @ (or
     * a tab / CR) get a leading apostrophe (CSV formula injection).
     */
    public static function csvCell($value): string
    {
        $value = (string)$value;
        return $value !== '' && strpbrk($value[0], "=+-@\t\r") !== false ? "'" . $value : $value;
    }

    /** @return array{from: ?\DateTime, to: ?\DateTime, actor: string, action: string, mailbox: string} */
    public static function filters(Request $request): array
    {
        $q = $request->query;
        $date = function (string $key) use ($q): ?\DateTime {
            $v = (string)$q->get($key, '');
            $d = preg_match('/^\d{4}-\d{2}-\d{2}$/', $v) ? \DateTime::createFromFormat('!Y-m-d', $v) : false;
            return $d ?: null;
        };
        $to = $date('to');
        $action = (string)$q->get('action', '');

        return [
            'from' => $date('from'),
            // Inclusive end date: everything before the next midnight.
            'to' => $to ? $to->modify('+1 day') : null,
            'actor' => mb_substr(trim((string)$q->get('actor', '')), 0, 180),
            'action' => preg_match('/^[a-z_]+(\.[a-z_]*)?$/', $action) ? $action : '',
            'mailbox' => mb_substr(trim((string)$q->get('mailbox', '')), 0, 255),
        ];
    }

    /** Filters back as URL query (pagination, export link). */
    private static function query(array $filters): array
    {
        return array_filter([
            'from' => $filters['from']?->format('Y-m-d'),
            'to' => $filters['to'] ? (clone $filters['to'])->modify('-1 day')->format('Y-m-d') : null,
            'actor' => $filters['actor'],
            'action' => $filters['action'],
            'mailbox' => $filters['mailbox'],
        ], fn($v) => $v !== null && $v !== '');
    }

    /** "rule." => "rule.*" style group filters for the dropdown. */
    private static function actionGroups(): array
    {
        $groups = [];
        foreach (array_keys(AuditLogger::ACTIONS) as $action) {
            $groups[strstr($action, '.', true) . '.'] = true;
        }
        return array_keys($groups);
    }
}
