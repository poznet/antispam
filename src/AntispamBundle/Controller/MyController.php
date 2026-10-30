<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\Jobs\JobQueue;
use AntispamBundle\Services\QuarantineDigestService;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\QuarantinePurge;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\SpamFolderService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

/**
 * End-user area (ROLE_USER; administrators may open it too and then see every
 * mailbox): own quarantine with release / whitelist / delete, own SPAM folder
 * with release / release + whitelist, own score log and the own password.
 *
 * Ownership is enforced here, server-side, on every query and every action
 * that takes an id from the request - see Security\MailboxAccess.
 */
#[Route('/my')]
class MyController extends AbstractController
{
    use AuditTrait;
    use JobQueueTrait;

    private const SCORELOG_PER_PAGE = 50;

    public function __construct(
        private EntityManagerInterface $em,
        private QuarantineService $quarantine,
        private MailboxAccess $access,
        private UserPasswordHasherInterface $hasher,
        private SpamFolderService $spam,
        private DeferredAgentSync $agentSync,
        private ?QuarantinePurge $purger = null,
        private ?JobQueue $jobs = null,
        private ?DeferredRetroactivePass $retroactive = null,
    ) {
    }

    #[Route('/quarantine', name: 'antispam_my_quarantine', methods: ['GET'])]
    #[Template('@Antispam/My/quarantine.html.twig')]
    public function quarantineAction()
    {
        $mailboxes = [];
        foreach ($this->access->filterMailboxes($this->getUser(), $this->quarantine->getMailboxes()) as $mailbox) {
            $items = [];
            $error = null;
            try {
                foreach ($this->quarantine->listItems($mailbox['key'], null, SpamboxController::QUARANTINE_LIST_LIMIT) as $item) {
                    $item['labels'] = QuarantineDigestService::reasonLabels($item['reasons']);
                    $item['high_risk'] = QuarantineDigestService::isHighRisk($item['reasons']);
                    $items[] = $item;
                }
            } catch (\Throwable $e) {
                // Raw exception text (hosts, paths) stays in the admin area.
                $error = 'Nie udało się odczytać kwarantanny tej skrzynki. Spróbuj później lub skontaktuj się z administratorem.';
            }
            $mailboxes[] = $mailbox + ['items' => $items, 'error' => $error] + SpamboxController::purgeCounts($items, SpamboxController::QUARANTINE_LIST_LIMIT);
        }

        return ['mailboxes' => $mailboxes];
    }

    /** Release (optionally whitelisting the sender) or delete a quarantined message of an own mailbox. */
    #[Route('/quarantine/action', name: 'antispam_my_quarantine_action', methods: ['POST'])]
    public function quarantineItemAction(Request $request)
    {
        if (!$this->isCsrfTokenValid('my_quarantine_action', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            return $this->redirectToRoute('antispam_my_quarantine');
        }

        $key = (string)$request->request->get('mailbox');
        $id = (string)$request->request->get('id');
        $action = (string)$request->request->get('action');

        // Ownership of the mailbox decides everything: the message id is only
        // ever resolved inside that mailbox's quarantine.
        if (!$this->access->canAccessMailboxKey($this->getUser(), $key)) {
            throw $this->createAccessDeniedException();
        }

        try {
            if ($action === 'whitelist' && $this->isHighRisk($key, $id)) {
                $result = ['success' => false, 'message' => 'Nadawcy tej wiadomości nie można dodać do białej listy (wysokie ryzyko).'];
            } else {
                $result = match ($action) {
                    'release' => $this->quarantine->release($key, $id),
                    'whitelist' => $this->quarantine->release($key, $id, true),
                    'delete' => $this->quarantine->delete($key, $id),
                    'blacklist' => $this->blacklist($key, $id),
                    default => ['success' => false, 'message' => 'Nieznana akcja'],
                };
            }
        } catch (\Throwable $e) {
            $result = ['success' => false, 'message' => 'Operacja nie powiodła się. Spróbuj ponownie lub skontaktuj się z administratorem.'];
        }
        $this->auditLogger()?->quarantine($action, 'my', $key, $id, $result);

        $this->addFlash($result['success'] ? 'success' : 'danger', $result['message']);
        return $this->redirectToRoute('antispam_my_quarantine');
    }

    /**
     * "Usuń wszystkie wysokiego ryzyka" / "Usuń wszystko z kwarantanny" of an
     * own mailbox, as a background job (quarantine.purge). The mailbox key is
     * checked first (403 for a foreign one); the job checks ownership again
     * when it runs and decides then what is deleted.
     */
    #[Route('/quarantine/purge', name: 'antispam_my_quarantine_purge', methods: ['POST'])]
    public function quarantinePurgeAction(Request $request)
    {
        if (!$this->isCsrfTokenValid('my_quarantine_purge', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            return $this->redirectToRoute('antispam_my_quarantine');
        }
        $key = (string)$request->request->get('mailbox');
        if (!$this->access->canAccessMailboxKey($this->getUser(), $key)) {
            throw $this->createAccessDeniedException();
        }
        $mode = (string)$request->request->get('mode');
        $mailbox = $this->quarantine->getMailbox($key);
        if (!QuarantinePurge::isMode($mode) || !$mailbox || $this->purger === null) {
            $this->addFlash('danger', 'Nieznana skrzynka lub tryb usuwania.');
            return $this->redirectToRoute('antispam_my_quarantine');
        }
        $minScore = null;
        if ($mode === QuarantineService::PURGE_MIN_SCORE) {
            $minScore = (int)$request->request->get('min_score');
            if ($minScore < 1 || $minScore > QuarantinePurge::MAX_MIN_SCORE) {
                $this->addFlash('danger', 'Podaj liczbę punktów od 1 do ' . QuarantinePurge::MAX_MIN_SCORE . '.');
                return $this->redirectToRoute('antispam_my_quarantine');
            }
        }

        $shown = $request->request->get('shown');
        $queued = $this->purger->enqueue($mailbox, $mode, QuarantinePurge::SOURCE_MY, is_numeric($shown) ? max(0, (int)$shown) : null, $this->getUser(), $minScore);
        $job = $this->jobs?->find($queued->id);
        if (!$job || !$this->mayViewJob($job)) {
            // Already queued by someone else (an administrator): not this user's job page.
            $this->addFlash('info', 'Usuwanie z kwarantanny tej skrzynki jest już w kolejce lub w trakcie - odśwież stronę za chwilę.');
            return $this->redirectToRoute('antispam_my_quarantine');
        }
        $this->flashQueued($queued, 'Trwałe usuwanie z kwarantanny');
        return $this->redirectToRoute('antispam_my_job_show', ['id' => $queued->id]);
    }

    /** Status and result of an own quarantine purge job (the admin job pages stay admin-only). */
    #[Route('/jobs/{id}', name: 'antispam_my_job_show', requirements: ['id' => '\d+'], methods: ['GET'])]
    #[Template('@Antispam/My/job.html.twig')]
    public function jobAction(int $id)
    {
        $job = $this->ownJob($id);
        return ['job' => $job, 'result' => $job->getResult(), 'is_admin' => $this->access->isAdmin($this->getUser())];
    }

    /** Polled by job-status.js on /my/jobs/{id}. */
    #[Route('/jobs/{id}/status', name: 'antispam_my_job_status', requirements: ['id' => '\d+'], methods: ['GET'])]
    public function jobStatusAction(int $id): JsonResponse
    {
        $response = new JsonResponse(JobController::statusData($this->ownJob($id)));
        $response->headers->set('Cache-Control', 'no-store');
        return $response;
    }

    /** 404 (not 403) for anything but an own purge job, so job ids reveal nothing. */
    private function ownJob(int $id): BackgroundJob
    {
        $job = $this->jobs?->find($id);
        if (!$job || !$this->mayViewJob($job)) {
            throw $this->createNotFoundException('Nie ma takiego zadania.');
        }
        return $job;
    }

    /**
     * Only quarantine purge jobs of a mailbox the user may access and - for a
     * ROLE_USER - only the ones this user queued.
     */
    private function mayViewJob(BackgroundJob $job): bool
    {
        if ($job->getType() !== BackgroundJob::TYPE_QUARANTINE_PURGE) {
            return false;
        }
        $user = $this->getUser();
        if (!$this->access->canAccessMailboxKey($user, (string)($job->getPayload()['key'] ?? ''))) {
            return false;
        }
        if ($this->access->isAdmin($user)) {
            return true;
        }
        return $user instanceof User
            && $job->getRequestedByType() === AuditLog::ACTOR_USER
            && $job->getRequestedBy() === (string)$user->getUsername();
    }

    /** Fail closed: a message that cannot be found in the listing is treated as high risk. */
    private function isHighRisk(string $key, string $id): bool
    {
        foreach ($this->quarantine->listItems($key, null, 500) as $item) {
            if ((string)$item['id'] === $id) {
                return QuarantineDigestService::isHighRisk($item['reasons']);
            }
        }
        return true;
    }

    /** Newest messages of the SPAM folder of each own mailbox (IMAP or SSH agent). */
    #[Route('/spam', name: 'antispam_my_spam', methods: ['GET'])]
    #[Template('@Antispam/My/spam.html.twig')]
    public function spamAction()
    {
        $mailboxes = [];
        foreach ($this->access->filterMailboxes($this->getUser(), $this->quarantine->getMailboxes()) as $mailbox) {
            $items = [];
            $total = 0;
            $error = null;
            try {
                $list = $this->spam->listItems($mailbox['key'], SpamFolderService::DEFAULT_LIMIT);
                $total = $list['total'];
                foreach ($list['items'] as $item) {
                    $item['labels'] = QuarantineDigestService::reasonLabels($item['reasons']);
                    $item['high_risk'] = QuarantineDigestService::isHighRisk($item['reasons']);
                    $items[] = $item;
                }
            } catch (\Throwable $e) {
                // Raw exception text (hosts, paths) stays in the admin area.
                $error = 'Nie udało się odczytać folderu SPAM tej skrzynki. Spróbuj później lub skontaktuj się z administratorem.';
            }
            $mailboxes[] = $mailbox + ['items' => $items, 'total' => $total, 'error' => $error];
        }

        return ['mailboxes' => $mailboxes, 'limit' => SpamFolderService::DEFAULT_LIMIT];
    }

    /** "Przywróć do skrzynki" / "Przywróć i zawsze akceptuj" from the SPAM folder of an own mailbox. */
    #[Route('/spam/action', name: 'antispam_my_spam_action', methods: ['POST'])]
    public function spamItemAction(Request $request)
    {
        if (!$this->isCsrfTokenValid('my_spam_action', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            return $this->redirectToRoute('antispam_my_spam');
        }

        $key = (string)$request->request->get('mailbox');
        $id = (string)$request->request->get('id');
        $action = (string)$request->request->get('action');
        $uidValidity = $request->request->get('uidvalidity');
        $uidValidity = is_numeric($uidValidity) ? (int)$uidValidity : null;

        // The key decides everything; the id is only looked up inside that mailbox.
        if (!$this->access->canAccessMailboxKey($this->getUser(), $key)) {
            throw $this->createAccessDeniedException();
        }

        try {
            if (!in_array($action, ['release', 'whitelist'], true)) {
                $result = ['success' => false, 'message' => 'Nieznana akcja', 'sender' => ''];
            } elseif ($action === 'whitelist' && $this->isSpamHighRisk($key, $id)) {
                $result = ['success' => false, 'message' => 'Nadawcy tej wiadomości nie można dodać do zaufanych (wysokie ryzyko lub brak zapisanej oceny). Możesz ją przywrócić bez akceptowania nadawcy.', 'sender' => ''];
            } else {
                $result = $this->spam->release($key, $id, $action === 'whitelist', $uidValidity);
            }
        } catch (\Throwable $e) {
            $result = ['success' => false, 'message' => 'Operacja nie powiodła się. Spróbuj ponownie lub skontaktuj się z administratorem.', 'sender' => ''];
        }

        $mailbox = $this->quarantine->getMailbox($key);
        $this->audit($action === 'whitelist' ? 'spam.whitelist' : 'spam.release', targetType: 'message', targetId: $id,
            label: ($result['sender'] ?? '') !== '' ? $result['sender'] : null, mailbox: $mailbox['account_email'] ?? null,
            details: ['source' => 'my', 'mailbox_id' => $key, 'ok' => (bool)$result['success']]);

        if ($result['success'] && !empty($result['whitelisted']) && $mailbox && str_starts_with($key, 'ssh-')) {
            // The agent whitelisted the sender locally already; the sync keeps it equal to the panel's list.
            $this->agentSync->deferForOwner((string)$mailbox['account_email']);
        }

        $this->addFlash($result['success'] ? 'success' : 'danger', $result['message']);
        return $this->redirectToRoute('antispam_my_spam');
    }

    /** Fail closed, like the quarantine: unlisted / unknown-score / risky messages get no whitelist. */
    private function isSpamHighRisk(string $key, string $id): bool
    {
        foreach ($this->spam->listItems($key, 500)['items'] as $item) {
            if ((string)$item['id'] === $id) {
                return QuarantineDigestService::isHighRisk($item['reasons']);
            }
        }
        return true;
    }

    /** Own score log: why a message was flagged. decision=spam is the "spam" view. */
    #[Route('/scorelog', name: 'antispam_my_scorelog', methods: ['GET'])]
    #[Template('@Antispam/Spambox/scorelog.html.twig')]
    public function scorelogAction(Request $request)
    {
        $user = $this->getUser();
        $repo = $this->em->getRepository(SpamScoreLog::class);
        $filters = $this->access->scopeScoreLogFilters($user, SpamboxController::scorelogFilters($request));
        $page = max(1, $request->query->getInt('page', 1));

        $result = $repo->search($filters, $page, self::SCORELOG_PER_PAGE);
        $pages = max(1, (int)ceil($result['total'] / self::SCORELOG_PER_PAGE));

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
            'accounts' => $this->access->accountEmails($user) ?? $repo->distinctAccounts(),
            'stats' => $repo->statsByDecision(new \DateTime('-30 days'), $filters['accounts'] ?? null),
            'scorelog_route' => 'antispam_my_scorelog',
        ];
    }

    /** Change the own password (users stored in the database; the env admin changes ADMIN_PASSWORD). */
    #[Route('/password', name: 'antispam_my_password', methods: ['GET', 'POST'])]
    public function passwordAction(Request $request)
    {
        $user = $this->getUser();
        if (!$user instanceof User) {
            $this->addFlash('warning', 'Hasło tego konta jest ustawiane w konfiguracji serwera (ADMIN_PASSWORD).');
            return $this->redirectToRoute('antispam_start');
        }

        if ($request->isMethod('POST')) {
            $current = (string)$request->request->get('current');
            $new = (string)$request->request->get('password');
            if (!$this->isCsrfTokenValid('my_password', (string)$request->request->get('_token'))) {
                $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            } elseif (!$this->hasher->isPasswordValid($user, $current)) {
                $this->addFlash('danger', 'Obecne hasło jest nieprawidłowe.');
            } elseif (mb_strlen($new) < UserController::MIN_PASSWORD_LENGTH) {
                $this->addFlash('danger', sprintf('Nowe hasło musi mieć co najmniej %d znaków.', UserController::MIN_PASSWORD_LENGTH));
            } elseif ($new !== (string)$request->request->get('password_repeat')) {
                $this->addFlash('danger', 'Hasła nie są takie same.');
            } else {
                // The session of this user stays valid only if we re-login; Symfony
                // would otherwise log the user out because the password hash changed.
                $user->setPassword($this->hasher->hashPassword($user, $new));
                $this->em->flush();
                $this->audit('user.password_change', targetType: 'user', targetId: $user->getId(), label: $user->getUsername());
                $this->addFlash('success', 'Hasło zostało zmienione. Zaloguj się ponownie.');
                return $this->redirectToRoute('logout');
            }
        }

        return $this->render('@Antispam/My/password.html.twig', ['min_password' => UserController::MIN_PASSWORD_LENGTH]);
    }

    /**
     * Sender of a quarantined message to the blacklist; its quarantined mail to
     * SPAM. A new rule gets its retroactive pass (INBOX of the last 30 days,
     * SSH agent rule sync), like a rule added on the blacklist page.
     */
    private function blacklist(string $key, string $id): array
    {
        $result = $this->quarantine->blacklist($key, $id);
        if (!empty($result['rule'])) {
            $this->audit('rule.add', targetType: 'email_blacklist', targetId: $result['rule']->getId(), label: $result['sender'], mailbox: $result['rule']->getEmail(),
                details: ['pattern_type' => 'exact', 'score' => $result['rule']->getScore(), 'source' => 'quarantine']);
            $this->retroactive?->queue($result['rule']);
        }
        return $result;
    }
}
