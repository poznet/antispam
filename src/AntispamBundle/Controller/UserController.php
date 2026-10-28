<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Administration of panel users (ROLE_ADMIN only - the catch-all access_control
 * rule in security.yaml): create / edit / delete, role, password and the
 * mailboxes a ROLE_USER may see.
 */
#[Route('/users')]
class UserController extends AbstractController
{
    use AuditTrait;

    const MIN_PASSWORD_LENGTH = 10;

    public function __construct(
        private EntityManagerInterface $em,
        private UserPasswordHasherInterface $hasher,
        #[Autowire('%env(ADMIN_USER)%')] private string $envAdminUser,
    ) {
    }

    #[Route('', name: 'antispam_user_index')]
    #[Template('@Antispam/User/index.html.twig')]
    public function indexAction()
    {
        return ['users' => $this->em->getRepository(User::class)->findBy([], ['username' => 'ASC']), 'env_admin' => $this->envAdminUser];
    }

    #[Route('/add', name: 'antispam_user_add')]
    public function addAction(Request $request)
    {
        $user = new User();
        $form = ['username' => '', 'role' => User::ROLE_USER, 'accounts' => []];

        if ($request->isMethod('POST')) {
            $this->checkToken($request, 'user_form');
            $data = $request->request->all('user');
            $form = $this->formData($data);
            $errors = $this->validate($user, $data, true);
            if (!$errors) {
                $this->apply($user, $data);
                $this->em->persist($user);
                $this->em->flush();
                $this->audit('user.add', targetType: 'user', targetId: $user->getId(), label: $user->getUsername(), details: $this->auditDetails($user, $data));
                $this->addFlash('success', sprintf('Użytkownik %s został utworzony.', $user->getUsername()));
                return $this->redirectToRoute('antispam_user_index');
            }
            foreach ($errors as $error) {
                $this->addFlash('danger', $error);
            }
        }

        return $this->render('@Antispam/User/form.html.twig', $this->formVars($user, $form));
    }

    #[Route('/edit/{id}', name: 'antispam_user_edit', requirements: ['id' => '\d+'])]
    public function editAction(int $id, Request $request)
    {
        $user = $this->em->getRepository(User::class)->find($id);
        if (!$user) {
            $this->addFlash('danger', 'Nie znaleziono użytkownika.');
            return $this->redirectToRoute('antispam_user_index');
        }
        $form = [
            'username' => $user->getUsername(),
            'role' => $user->getRole(),
            'accounts' => array_map(fn(Account $a) => (int)$a->getId(), $user->getAccounts()->toArray()),
        ];

        if ($request->isMethod('POST')) {
            $this->checkToken($request, 'user_form');
            $data = $request->request->all('user');
            $form = $this->formData($data);
            $errors = $this->validate($user, $data, false);
            if (!$errors) {
                $this->apply($user, $data);
                $this->em->flush();
                $this->audit('user.edit', targetType: 'user', targetId: $user->getId(), label: $user->getUsername(), details: $this->auditDetails($user, $data));
                $this->addFlash('success', sprintf('Zapisano zmiany użytkownika %s.', $user->getUsername()));
                return $this->redirectToRoute('antispam_user_index');
            }
            foreach ($errors as $error) {
                $this->addFlash('danger', $error);
            }
        }

        return $this->render('@Antispam/User/form.html.twig', $this->formVars($user, $form));
    }

    #[Route('/del/{id}', name: 'antispam_user_del', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function deleteAction(int $id, Request $request)
    {
        $this->checkToken($request, 'user_action_' . $id);
        $user = $this->em->getRepository(User::class)->find($id);
        if (!$user) {
            $this->addFlash('danger', 'Nie znaleziono użytkownika.');
        } elseif ($this->isSelf($user)) {
            $this->addFlash('danger', 'Nie możesz usunąć własnego konta.');
        } else {
            $this->em->remove($user);
            $this->em->flush();
            $this->audit('user.delete', targetType: 'user', targetId: $id, label: $user->getUsername(), details: ['role' => $user->getRole()]);
            $this->addFlash('success', sprintf('Użytkownik %s został usunięty.', $user->getUsername()));
        }
        return $this->redirectToRoute('antispam_user_index');
    }

    private function checkToken(Request $request, string $tokenId): void
    {
        if (!$this->isCsrfTokenValid($tokenId, (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }

    private function isSelf(User $user): bool
    {
        $current = $this->getUser();
        return $current instanceof User && $current->getId() === $user->getId();
    }

    private function formData(array $data): array
    {
        return [
            'username' => trim((string)($data['username'] ?? '')),
            'role' => (string)($data['role'] ?? User::ROLE_USER),
            'accounts' => array_map('intval', array_filter((array)($data['accounts'] ?? []), 'is_scalar')),
        ];
    }

    private function formVars(User $user, array $form): array
    {
        return [
            'user_entity' => $user,
            'form' => $form,
            'roles' => User::ROLES,
            'accounts' => $this->em->getRepository(Account::class)->findBy([], ['name' => 'ASC']),
            'min_password' => self::MIN_PASSWORD_LENGTH,
            'is_self' => $user->getId() !== null && $this->isSelf($user),
        ];
    }

    /** @return string[] error messages (Polish) */
    private function validate(User $user, array $data, bool $creating): array
    {
        $errors = [];
        $form = $this->formData($data);
        $username = $form['username'];

        if (strlen($username) < 3 || strlen($username) > 180 || !preg_match('/^[A-Za-z0-9._@+-]+$/', $username)) {
            $errors[] = 'Login musi mieć 3-180 znaków: litery, cyfry oraz . _ @ + -';
        } else {
            if ($this->envAdminUser !== '' && strcasecmp($username, $this->envAdminUser) === 0) {
                $errors[] = 'Ten login jest zarezerwowany dla administratora z konfiguracji serwera (ADMIN_USER).';
            }
            $existing = $this->em->getRepository(User::class)->findOneBy(['username' => $username]);
            if ($existing && $existing->getId() !== $user->getId()) {
                $errors[] = 'Użytkownik o takim loginie już istnieje.';
            }
        }

        if (!in_array($form['role'], User::ROLES, true)) {
            $errors[] = 'Nieprawidłowa rola.';
        } elseif ($form['role'] !== User::ROLE_ADMIN && $user->getId() !== null && $this->isSelf($user)) {
            $errors[] = 'Nie możesz odebrać sobie roli administratora.';
        }

        $password = (string)($data['password'] ?? '');
        if (($creating || $password !== '') && mb_strlen($password) < self::MIN_PASSWORD_LENGTH) {
            $errors[] = sprintf('Hasło musi mieć co najmniej %d znaków.', self::MIN_PASSWORD_LENGTH);
        }
        if ($password !== '' && $password !== (string)($data['password_repeat'] ?? '')) {
            $errors[] = 'Hasła nie są takie same.';
        }

        if ($form['accounts'] && count($this->findAccounts($form['accounts'])) !== count(array_unique($form['accounts']))) {
            $errors[] = 'Wybrano nieistniejącą skrzynkę.';
        }

        return $errors;
    }

    /** @return Account[] */
    private function findAccounts(array $ids): array
    {
        return $ids ? $this->em->getRepository(Account::class)->findBy(['id' => array_values(array_unique($ids))]) : [];
    }

    /** Role, mailboxes and whether the password was set - never the password. */
    private function auditDetails(User $user, array $data): array
    {
        return [
            'role' => $user->getRole(),
            'mailboxes' => array_map(fn(Account $a) => (string)$a->getEmail(), $user->getAccounts()->toArray()),
            'password_changed' => (string)($data['password'] ?? '') !== '',
        ];
    }

    private function apply(User $user, array $data): void
    {
        $form = $this->formData($data);
        $user->setUsername($form['username'])->setRole($form['role']);
        $user->setAccounts($this->findAccounts($form['accounts']));
        $password = (string)($data['password'] ?? '');
        if ($password !== '') {
            $user->setPassword($this->hasher->hashPassword($user, $password));
        }
    }
}
