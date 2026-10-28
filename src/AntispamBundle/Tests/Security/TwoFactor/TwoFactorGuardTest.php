<?php

namespace AntispamBundle\Tests\Security\TwoFactor;

use AntispamBundle\Entity\User;
use AntispamBundle\Security\TwoFactor\TwoFactorGuard;
use AntispamBundle\Security\TwoFactor\TwoFactorService;
use AntispamBundle\Tests\Support\TwoFactorFixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\AccessMapInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * The second login step blocks every non-public route until the code was
 * given, and an enforced setup blocks everything but the setup page.
 */
class TwoFactorGuardTest extends TestCase
{
    private TwoFactorFixtures $fx;
    private TwoFactorService $tf;
    private Session $session;

    protected function setUp(): void
    {
        $this->fx = new TwoFactorFixtures($this);
        $this->tf = $this->fx->service(TwoFactorFixtures::ENV_SECRET);
        $this->session = new Session(new MockArraySessionStorage());
    }

    private function guard(?object $user, bool $public = false): TwoFactorGuard
    {
        $tokens = new TokenStorage();
        if ($user) {
            $tokens->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        }
        $urls = $this->createMock(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturnCallback(fn($name) => '/' . $name);
        $map = $this->createMock(AccessMapInterface::class);
        $map->method('getPatterns')->willReturn([$public ? ['PUBLIC_ACCESS'] : ['ROLE_ADMIN'], null]);
        return new TwoFactorGuard($tokens, $this->tf, $urls, $map);
    }

    private function dispatch(TwoFactorGuard $guard, string $route): ?string
    {
        $request = Request::create('/x');
        $request->attributes->set('_route', $route);
        $request->setSession($this->session);
        $event = new RequestEvent($this->createMock(HttpKernelInterface::class), $request, HttpKernelInterface::MAIN_REQUEST);
        $guard->onRequest($event);
        $response = $event->getResponse();
        return $response instanceof RedirectResponse ? $response->getTargetUrl() : null;
    }

    private function enrolledUser(string $role = User::ROLE_USER): User
    {
        $user = TwoFactorFixtures::user($role);
        TwoFactorFixtures::enroll($this->tf, $user);
        return $user;
    }

    public static function protectedRoutes(): array
    {
        return [['antispam_index'], ['antispam_my_quarantine'], ['antispam_my_2fa'], ['antispam_my_2fa_disable'], ['antispam_user_index'], ['antispam_start'], ['']];
    }

    #[DataProvider('protectedRoutes')]
    public function testPendingCodeRedirectsEverythingToTheCodeForm(string $route)
    {
        $this->assertSame('/antispam_2fa_verify', $this->dispatch($this->guard($this->enrolledUser()), $route));
    }

    public function testCodeFormAndLogoutStayReachable()
    {
        $guard = $this->guard($this->enrolledUser());
        $this->assertNull($this->dispatch($guard, 'antispam_2fa_verify'));
        $this->assertNull($this->dispatch($guard, 'logout'));
    }

    public function testPassedSessionIsLetThrough()
    {
        $user = $this->enrolledUser();
        $this->tf->markPassed($this->session, $user);
        $this->assertNull($this->dispatch($this->guard($user), 'antispam_index'));
    }

    public function testPublicPathsAreNotGuarded()
    {
        $this->assertNull($this->dispatch($this->guard($this->enrolledUser(), true), 'antispam_quarantine_action'));
    }

    public function testUserWithout2faIsNotGuarded()
    {
        $this->assertNull($this->dispatch($this->guard(TwoFactorFixtures::user(User::ROLE_ADMIN)), 'antispam_index'));
    }

    public function testEnvAdminWithSecretMustGiveTheCode()
    {
        $admin = new InMemoryUser('admin', 'h', ['ROLE_ADMIN']);
        $this->assertSame('/antispam_2fa_verify', $this->dispatch($this->guard($admin), 'antispam_index'));
        $this->tf->markPassed($this->session, $admin);
        $this->assertNull($this->dispatch($this->guard($admin), 'antispam_index'));
    }

    public function testEnforcementSendsAdminsWithout2faToTheSetupPage()
    {
        $this->tf->setRequiredForAdmins(true);
        $admin = TwoFactorFixtures::user(User::ROLE_ADMIN);
        $guard = $this->guard($admin);
        $this->assertSame('/antispam_my_2fa', $this->dispatch($guard, 'antispam_index'));
        $this->assertSame('/antispam_my_2fa', $this->dispatch($guard, 'antispam_my_quarantine'));
        $this->assertNull($this->dispatch($guard, 'antispam_my_2fa'));
        $this->assertNull($this->dispatch($guard, 'antispam_my_2fa_enable'));
        $this->assertNull($this->dispatch($guard, 'logout'));
        $this->assertArrayHasKey('warning', $this->session->getFlashBag()->peekAll());

        // Users and the env admin (no secret) are not forced.
        $this->assertNull($this->dispatch($this->guard(TwoFactorFixtures::user(User::ROLE_USER)), 'antispam_my_quarantine'));
        $noSecret = (new TwoFactorFixtures($this))->service('');
        $noSecret->setRequiredForAdmins(true);
        $this->assertFalse($noSecret->needsSetup(new InMemoryUser('admin', 'h', ['ROLE_ADMIN'])));
    }

    public function testNewLoginDropsThePassedMarker()
    {
        $user = $this->enrolledUser();
        $this->tf->markPassed($this->session, $user);
        $request = Request::create('/login', 'POST');
        $request->setSession($this->session);
        $passport = new SelfValidatingPassport(new UserBadge('jan', fn() => $user));
        $event = new LoginSuccessEvent($this->createMock(AuthenticatorInterface::class), $passport,
            new UsernamePasswordToken($user, 'main', $user->getRoles()), $request, null, 'main');

        $this->guard($user)->onLoginSuccess($event);

        $this->assertFalse($this->tf->isPassed($this->session, $user));
        $this->assertSame('/antispam_2fa_verify', $this->dispatch($this->guard($user), 'antispam_index'));
    }
}
