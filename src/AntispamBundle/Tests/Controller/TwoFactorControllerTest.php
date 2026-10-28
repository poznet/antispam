<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\TwoFactorController;
use AntispamBundle\Controller\UserController;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\TwoFactor\QrCodeRenderer;
use AntispamBundle\Security\TwoFactor\Totp;
use AntispamBundle\Security\TwoFactor\TwoFactorGuard;
use AntispamBundle\Security\TwoFactor\TwoFactorService;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Tests\Support\InMemoryRepository;
use AntispamBundle\Tests\Support\RecordingAuditLogger;
use AntispamBundle\Tests\Support\TwoFactorFixtures;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\AccessMapInterface;
use Twig\Environment;

/**
 * 2FA setup / login step / disable / backup codes and the admin reset:
 * codes are checked, wrong ones and throttled ones are refused and audited,
 * CSRF is required, disabling needs password + code.
 */
class TwoFactorControllerTest extends TestCase
{
    private TwoFactorFixtures $fx;
    private TwoFactorService $tf;
    private RecordingAuditLogger $audit;
    private Session $session;
    private bool $csrfValid = true;
    /** @var array{0: string, 1: array}|null last render() call */
    private ?array $rendered = null;

    protected function setUp(): void
    {
        $this->fx = new TwoFactorFixtures($this);
        $this->tf = $this->fx->service(TwoFactorFixtures::ENV_SECRET, TwoFactorFixtures::limiter(5));
        $this->audit = new RecordingAuditLogger();
        $this->session = new Session(new MockArraySessionStorage());
    }

    private function controller(object $user): TwoFactorController
    {
        $tokens = new TokenStorage();
        $tokens->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        $urls = $this->createMock(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturnCallback(fn($name) => '/' . $name);
        $map = $this->createMock(AccessMapInterface::class);
        $map->method('getPatterns')->willReturn([['ROLE_USER'], null]);
        $hasher = $this->createMock(UserPasswordHasherInterface::class);
        $hasher->method('isPasswordValid')->willReturnCallback(fn($u, $p) => $p === 'correct horse');

        $controller = new TwoFactorController($this->tf, new QrCodeRenderer(), $hasher, new TwoFactorGuard($tokens, $this->tf, $urls, $map));
        $this->wire($controller, $tokens);
        return $controller;
    }

    private function wire(AbstractController $controller, TokenStorage $tokens): void
    {
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturnCallback(fn() => $this->csrfValid);
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(fn($name) => '/' . $name);
        $twig = $this->createMock(Environment::class);
        $twig->method('render')->willReturnCallback(function ($name, $vars) {
            $this->rendered = [$name, $vars];
            return 'rendered';
        });
        $stack = new RequestStack();
        $request = new Request();
        $request->setSession($this->session);
        $stack->push($request);
        $controller->setContainer(new ServiceLocator([
            'security.token_storage' => fn() => $tokens,
            'security.csrf.token_manager' => fn() => $csrf,
            'router' => fn() => $router,
            'request_stack' => fn() => $stack,
            'twig' => fn() => $twig,
            AuditLogger::class => fn() => $this->audit,
        ]));
    }

    private function post(string $path, array $data): Request
    {
        $request = Request::create($path, 'POST', $data + ['_token' => 't']);
        $request->setSession($this->session);
        return $request;
    }

    private function get(string $path): Request
    {
        $request = Request::create($path);
        $request->setSession($this->session);
        return $request;
    }

    private function flashes(): array
    {
        return $this->session->getFlashBag()->all();
    }

    private function actions(): array
    {
        return array_column($this->audit->entries, 'action');
    }

    // ---- setup ---------------------------------------------------------------

    public function testSetupPageShowsALocalQrCodeOfThePendingSecret()
    {
        $user = TwoFactorFixtures::user();
        $this->controller($user)->settingsAction($this->get('/my/2fa'));

        [$template, $vars] = $this->rendered;
        $this->assertSame('@Antispam/TwoFactor/settings.html.twig', $template);
        $this->assertStringStartsWith('data:image/svg+xml;base64,', $vars['qr']);
        $this->assertStringContainsString('<svg', base64_decode(substr($vars['qr'], strlen('data:image/svg+xml;base64,'))));
        $this->assertSame($this->tf->pendingSecret($this->session), str_replace(' ', '', $vars['secret']));
        $this->assertFalse($user->isTotpEnabled(), 'nothing is stored before the confirmation');
    }

    public function testEnableNeedsAValidCodeOfThePendingSecret()
    {
        $user = TwoFactorFixtures::user();
        $controller = $this->controller($user);
        $secret = $this->tf->pendingSecret($this->session);

        $controller->enableAction($this->post('/my/2fa/enable', ['code' => '000000' === Totp::code($secret, Totp::counterAt()) ? '111111' : '000000']));
        $this->assertFalse($user->isTotpEnabled());
        $this->assertSame(['auth.2fa_failed'], $this->actions());
        $this->assertSame(['step' => 'enable', 'reason' => 'wrong_code'], $this->audit->last()['details']);

        $controller->enableAction($this->post('/my/2fa/enable', ['code' => Totp::code($secret, Totp::counterAt())]));
        $this->assertTrue($user->isTotpEnabled());
        $this->assertSame('auth.2fa_enabled', $this->audit->last()['action']);
        $this->assertSame('@Antispam/TwoFactor/backup_codes.html.twig', $this->rendered[0]);
        $this->assertCount(TwoFactorService::BACKUP_CODE_COUNT, $this->rendered[1]['codes']);
        $this->assertTrue($this->tf->isPassed($this->session, $user), 'the enabling session already proved the factor');
        $this->assertNull($this->session->get(TwoFactorService::SESSION_PENDING_SECRET));
    }

    public function testEnableRequiresCsrf()
    {
        $user = TwoFactorFixtures::user();
        $secret = $this->tf->pendingSecret($this->session);
        $this->csrfValid = false;
        $this->controller($user)->enableAction($this->post('/my/2fa/enable', ['code' => Totp::code($secret, Totp::counterAt())]));
        $this->assertFalse($user->isTotpEnabled());
    }

    // ---- login step ------------------------------------------------------------

    public function testLoginStepAcceptsTheCodeAndMarksTheSession()
    {
        $user = TwoFactorFixtures::user();
        [$secret] = TwoFactorFixtures::enroll($this->tf, $user);
        $controller = $this->controller($user);

        $response = $controller->verifyAction($this->post('/2fa', ['code' => Totp::code($secret, Totp::counterAt())]));
        $this->assertSame('/antispam_start', $response->getTargetUrl());
        $this->assertTrue($this->tf->isPassed($this->session, $user));
        $this->assertSame(['action' => 'auth.2fa_verified', 'method' => 'totp'], ['action' => $this->audit->last()['action'], 'method' => $this->audit->last()['details']['method']]);
    }

    public function testLoginStepAcceptsABackupCodeOnce()
    {
        $user = TwoFactorFixtures::user();
        [, $codes] = TwoFactorFixtures::enroll($this->tf, $user);

        $this->controller($user)->verifyAction($this->post('/2fa', ['code' => $codes[0]]));
        $this->assertTrue($this->tf->isPassed($this->session, $user));
        $this->assertSame('backup', $this->audit->last()['details']['method']);

        $this->tf->clearPassed($this->session);
        $this->controller($user)->verifyAction($this->post('/2fa', ['code' => $codes[0]]));
        $this->assertFalse($this->tf->isPassed($this->session, $user));
        $this->assertSame('auth.2fa_failed', $this->audit->last()['action']);
    }

    public function testWrongCodesAreThrottledAndAudited()
    {
        $user = TwoFactorFixtures::user();
        [$secret] = TwoFactorFixtures::enroll($this->tf, $user);
        $controller = $this->controller($user);
        $wrong = '000000' === Totp::code($secret, Totp::counterAt()) ? '111111' : '000000';

        for ($i = 0; $i < 5; $i++) {
            $controller->verifyAction($this->post('/2fa', ['code' => $wrong]));
            $this->assertSame('wrong_code', $this->audit->last()['details']['reason']);
        }
        // Even the right code is refused now - the limit is checked first.
        $controller->verifyAction($this->post('/2fa', ['code' => Totp::code($secret, Totp::counterAt())]));
        $this->assertFalse($this->tf->isPassed($this->session, $user));
        $this->assertSame(['step' => 'login', 'reason' => 'throttled'], $this->audit->last()['details']);
        $this->assertStringContainsString('Zbyt wiele', implode(' ', $this->flashes()['danger']));
    }

    public function testEnvAdminLoginStep()
    {
        $admin = new InMemoryUser('admin', 'h', ['ROLE_ADMIN']);
        $controller = $this->controller($admin);
        $controller->verifyAction($this->post('/2fa', ['code' => 'abcde-fghjk']));
        $this->assertFalse($this->tf->isPassed($this->session, $admin));

        $controller->verifyAction($this->post('/2fa', ['code' => Totp::code(TwoFactorFixtures::ENV_SECRET, Totp::counterAt())]));
        $this->assertTrue($this->tf->isPassed($this->session, $admin));
    }

    public function testCodeFormIsSkippedWhenNothingIsPending()
    {
        $user = TwoFactorFixtures::user();
        $response = $this->controller($user)->verifyAction($this->get('/2fa'));
        $this->assertSame('/antispam_start', $response->getTargetUrl());
    }

    // ---- disable / backup codes ---------------------------------------------------

    public function testDisableNeedsPasswordAndCode()
    {
        $user = TwoFactorFixtures::user();
        [$secret] = TwoFactorFixtures::enroll($this->tf, $user);
        $controller = $this->controller($user);

        $controller->disableAction($this->post('/my/2fa/disable', ['current' => 'wrong', 'code' => Totp::code($secret, Totp::counterAt())]));
        $this->assertTrue($user->isTotpEnabled());
        $this->assertSame('wrong_password', $this->audit->last()['details']['reason']);

        $controller->disableAction($this->post('/my/2fa/disable', ['current' => 'correct horse', 'code' => '12345']));
        $this->assertTrue($user->isTotpEnabled());
        $this->assertSame('wrong_code', $this->audit->last()['details']['reason']);

        $controller->disableAction($this->post('/my/2fa/disable', ['current' => 'correct horse', 'code' => Totp::code($secret, Totp::counterAt())]));
        $this->assertFalse($user->isTotpEnabled());
        $this->assertSame('auth.2fa_disabled', $this->audit->last()['action']);
    }

    public function testAdminCannotDisableWhileEnforced()
    {
        $admin = TwoFactorFixtures::user(User::ROLE_ADMIN);
        [$secret] = TwoFactorFixtures::enroll($this->tf, $admin);
        $this->tf->setRequiredForAdmins(true);

        $this->controller($admin)->disableAction($this->post('/my/2fa/disable', ['current' => 'correct horse', 'code' => Totp::code($secret, Totp::counterAt())]));
        $this->assertTrue($admin->isTotpEnabled());
        $this->assertNotContains('auth.2fa_disabled', $this->actions());
    }

    public function testRegenerateBackupCodes()
    {
        $user = TwoFactorFixtures::user();
        [$secret, $old] = TwoFactorFixtures::enroll($this->tf, $user);
        $this->controller($user)->backupCodesAction($this->post('/my/2fa/backup-codes', ['current' => 'correct horse', 'code' => Totp::code($secret, Totp::counterAt())]));

        $this->assertSame('auth.2fa_backup_codes', $this->audit->last()['action']);
        $new = $this->rendered[1]['codes'];
        $this->assertNull($this->tf->verify($user, $old[1]));
        $this->assertSame(TwoFactorService::METHOD_BACKUP, $this->tf->verify($user, $new[1]));
    }

    // ---- admin: reset + policy ----------------------------------------------------

    private function userController(object $admin, array $users): UserController
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn(new InMemoryRepository($users));
        $controller = new UserController($em, $this->createMock(UserPasswordHasherInterface::class), 'admin', $this->tf);
        $tokens = new TokenStorage();
        $tokens->setToken(new UsernamePasswordToken($admin, 'main', $admin->getRoles()));
        $this->wire($controller, $tokens);
        return $controller;
    }

    public function testAdminResetsAUsers2fa()
    {
        $ola = TwoFactorFixtures::user(User::ROLE_USER, 8, 'ola');
        TwoFactorFixtures::enroll($this->tf, $ola);
        $controller = $this->userController(new InMemoryUser('admin', 'h', ['ROLE_ADMIN']), [$ola]);

        $controller->resetTwoFactorAction(8, $this->post('/users/2fa-reset/8', []));
        $this->assertFalse($ola->isTotpEnabled());
        $this->assertSame(['auth.2fa_reset', 8, 'ola'], [$this->audit->last()['action'], $this->audit->last()['targetId'], $this->audit->last()['label']]);
    }

    public function testResetRequiresCsrf()
    {
        $ola = TwoFactorFixtures::user(User::ROLE_USER, 8, 'ola');
        TwoFactorFixtures::enroll($this->tf, $ola);
        $controller = $this->userController(new InMemoryUser('admin', 'h', ['ROLE_ADMIN']), [$ola]);
        $this->csrfValid = false;

        try {
            $controller->resetTwoFactorAction(8, $this->post('/users/2fa-reset/8', []));
            $this->fail('expected 403');
        } catch (AccessDeniedException) {
        }
        $this->assertTrue($ola->isTotpEnabled());
    }

    public function testPolicyToggle()
    {
        $controller = $this->userController(new InMemoryUser('admin', 'h', ['ROLE_ADMIN']), []);
        $controller->twoFactorPolicyAction($this->post('/users/2fa-policy', ['required' => '1']));
        $this->assertTrue($this->tf->isRequiredForAdmins());
        $this->assertSame(['settings.save', '2fa_policy', true], [$this->audit->last()['action'], $this->audit->last()['targetId'], $this->audit->last()['details']['required']]);

        $controller->twoFactorPolicyAction($this->post('/users/2fa-policy', ['required' => '0']));
        $this->assertFalse($this->tf->isRequiredForAdmins());
    }
}
