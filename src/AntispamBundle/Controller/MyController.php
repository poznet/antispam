<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\QuarantineDigestService;
use AntispamBundle\Services\QuarantineService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

/**
 * End-user area (ROLE_USER; administrators may open it too and then see every
 * mailbox): own quarantine with release / whitelist / delete, own score log
 * (also the "spam" view - filter decision=spam) and the own password.
 *
 * Ownership is enforced here, server-side, on every query and every action
 * that takes an id from the request - see Security\MailboxAccess.
 */
#[Route('/my')]
class MyController extends AbstractController
{
    private const SCORELOG_PER_PAGE = 50;

    public function __construct(
        private EntityManagerInterface $em,
        private QuarantineService $quarantine,
        private MailboxAccess $access,
        private UserPasswordHasherInterface $hasher,
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
                foreach ($this->quarantine->listItems($mailbox['key'], null, 100) as $item) {
                    $item['labels'] = QuarantineDigestService::reasonLabels($item['reasons']);
                    $item['high_risk'] = QuarantineDigestService::isHighRisk($item['reasons']);
                    $items[] = $item;
                }
            } catch (\Throwable $e) {
                // Raw exception text (hosts, paths) stays in the admin area.
                $error = 'Nie udało się odczytać kwarantanny tej skrzynki. Spróbuj później lub skontaktuj się z administratorem.';
            }
            $mailboxes[] = $mailbox + ['items' => $items, 'error' => $error];
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
                    default => ['success' => false, 'message' => 'Nieznana akcja'],
                };
            }
        } catch (\Throwable $e) {
            $result = ['success' => false, 'message' => 'Operacja nie powiodła się. Spróbuj ponownie lub skontaktuj się z administratorem.'];
        }

        $this->addFlash($result['success'] ? 'success' : 'danger', $result['message']);
        return $this->redirectToRoute('antispam_my_quarantine');
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
                $this->addFlash('success', 'Hasło zostało zmienione. Zaloguj się ponownie.');
                return $this->redirectToRoute('logout');
            }
        }

        return $this->render('@Antispam/My/password.html.twig', ['min_password' => UserController::MIN_PASSWORD_LENGTH]);
    }
}
