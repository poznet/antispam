<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\AccountController;
use AntispamBundle\Controller\OAuthController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\User;
use AntispamBundle\Services\ImapFlags;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\MailboxSettings;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

/** OAuth pages: admin only, templates render, account form validation, endpoint rules. */
class OAuthTemplatesAndAccessTest extends WebTestCase
{
    public static function paths(): array
    {
        return [['/config/oauth/'], ['/account/oauth/callback'], ['/account/oauth/connect/1'], ['/account/oauth/disconnect/1']];
    }

    #[DataProvider('paths')]
    public function testAccessControlRequiresAdmin(string $path)
    {
        self::bootKernel();
        [$attributes] = self::getContainer()->get('security.access_map')->getPatterns(Request::create($path));
        $this->assertSame(['ROLE_ADMIN'], $attributes);
    }

    public function testRoleUserIsRefusedByTheController()
    {
        self::bootKernel();
        $c = self::getContainer();
        $jan = (new User())->setUsername('jan')->setRole(User::ROLE_USER);
        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($jan, 'main', $jan->getRoles()));
        $this->expectException(AccessDeniedException::class);
        $c->get('controller.is_granted_attribute_listener')->onKernelControllerArguments(new ControllerArgumentsEvent(
            self::$kernel, [$c->get(OAuthController::class), 'callbackAction'], [new Request()], new Request(), HttpKernelInterface::MAIN_REQUEST));
    }

    public function testAnonymousCallbackGoesToTheLogin()
    {
        $client = static::createClient();
        $client->request('GET', '/account/oauth/callback?state=x&code=y');
        $this->assertSame(302, $client->getResponse()->getStatusCode());
        $this->assertStringContainsString('/login', (string)$client->getResponse()->headers->get('Location'));
    }

    private function render(string $template, array $vars): string
    {
        self::bootKernel();
        $request = Request::create('/');
        $request->setSession(new Session(new MockArraySessionStorage()));
        self::getContainer()->get('request_stack')->push($request);
        return self::getContainer()->get('twig')->render($template, $vars);
    }

    private static function account(string $method): Account
    {
        $a = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP)->setImapFlags('/imap/ssl')->setImapAuthMethod($method);
        (new \ReflectionProperty(Account::class, 'id'))->setValue($a, 7);
        return $a;
    }

    public function testEditPageShowsConnectAndDisconnect()
    {
        $account = self::account(Account::AUTH_OAUTH_MICROSOFT)->setOAuthRefreshToken('enc')->setOAuthUsername('jan@firma.pl')->setOAuthConnectedAt(new \DateTime())->setOAuthError('OAuth: invalid_grant');
        $html = $this->render('@Antispam/Account/edit.html.twig', [
            'account' => $account,
            'global_settings' => new MailboxSettings(10, 5, true, false, true, null, null),
            'imap_tls' => ImapFlags::parse('/imap/ssl'),
            'imap_flags' => '/imap/ssl',
            'oauth_configured' => ['microsoft' => true, 'google' => false],
        ]);
        $this->assertStringContainsString('<option value="oauth_microsoft" selected>', $html);
        $this->assertMatchesRegularExpression('~href="/account/oauth/connect/7\?_token=[^"]+"~', $html);
        $this->assertStringContainsString('action="/account/oauth/disconnect/7"', $html);
        $this->assertStringContainsString('OAuth: invalid_grant', $html);
        $this->assertStringContainsString('hasło wtyczki', $html);
        $this->assertStringContainsString('Google nie jest jeszcze skonfigurowany', $html);
    }

    public function testListShowsTokenErrors()
    {
        $html = $this->render('@Antispam/Account/index.html.twig', ['accounts' => [
            self::account(Account::AUTH_OAUTH_GOOGLE)->setOAuthRefreshToken('x')->setOAuthError('revoked'),
            self::account(Account::AUTH_OAUTH_MICROSOFT),
        ]]);
        $this->assertStringContainsString('OAuth Google: błąd tokenu', $html);
        $this->assertStringContainsString('OAuth Microsoft 365: niepołączone', $html);
    }

    public function testSettingsPageRenders()
    {
        $html = $this->render('@Antispam/Configuration/oauthConfig.html.twig', [
            'redirect_uri' => 'https://as.example.pl/account/oauth/callback', 'redirect_https' => true, 'public_url' => 'https://as.example.pl',
            'ms_client_id' => 'id', 'ms_secret_set' => true, 'ms_tenant' => '', 'google_client_id' => '', 'google_secret_set' => false,
            'accounts' => [self::account(Account::AUTH_OAUTH_MICROSOFT_APP)],
        ]);
        $this->assertStringContainsString('https://as.example.pl/account/oauth/callback', $html);
        $this->assertStringContainsString('IMAP.AccessAsUser.All', $html);
        $this->assertStringContainsString('(aplikacja)', $html);
        $this->assertStringNotContainsString('value="ms-secret"', $html);
    }

    public function testAccountValidationForOAuth()
    {
        $base = ['email' => 'jan@firma.pl', 'connection_type' => 'imap', 'imap_host' => '', 'imap_auth_method' => 'oauth_google', 'imap_flags' => '/imap/ssl'];
        $this->assertSame([], AccountController::validateAccountData($base), 'OAuth: empty host = provider default');
        $this->assertNotSame([], AccountController::validateAccountData(['imap_auth_method' => 'password'] + $base), 'password login still needs a host');
        $this->assertNotSame([], AccountController::validateAccountData(['imap_auth_method' => 'oauth_magic'] + $base));
        $this->assertNotSame([], AccountController::validateAccountData(['oauth_tenant' => 'a/b'] + $base));
        $this->assertNotSame([], AccountController::validateAccountData(['imap_flags' => '/imap/notls'] + $base), 'no token over plain text');
    }

    public function testOAuthEndpointDefaultsAndEncryption()
    {
        $a = self::account(Account::AUTH_OAUTH_GOOGLE);
        $this->assertSame(['imap.gmail.com', 993, 'ssl', true], ImapScanService::oauthEndpoint($a));
        $a->setImapHost('imap.firma.pl')->setImapPort(143)->setImapFlags('/imap');
        $this->assertSame(['imap.firma.pl', 143, 'tls', true], ImapScanService::oauthEndpoint($a), 'opportunistic STARTTLS becomes required');
        $a->setImapFlags('/imap/notls');
        $this->expectException(\RuntimeException::class);
        ImapScanService::oauthEndpoint($a);
    }
}
