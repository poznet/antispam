<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\OAuthController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\OAuth\OAuthClient;
use AntispamBundle\Services\OAuth\OAuthTokenManager;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Tests\Services\OAuth\OAuthTestCase;
use AntispamBundle\Tests\Support\InMemoryRepository;
use AntispamBundle\Tests\Support\RecordingAuditLogger;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Connect (state + PKCE in the session), callback validation and disconnect,
 * with the provider's token endpoint mocked.
 */
class OAuthControllerTest extends OAuthTestCase
{
    private Session $session;
    private RecordingAuditLogger $audit;
    private RequestStack $stack;
    private bool $csrfValid = true;
    private int $flushes = 0;
    /** @var MockResponse[] */
    private array $responses = [];
    private array $bodies = [];
    private Account $account;

    private function controller(?Account $account = null): OAuthController
    {
        $this->account = $account ?? $this->account(Account::AUTH_OAUTH_MICROSOFT);
        $this->session = $this->session ?? new Session(new MockArraySessionStorage());
        $this->audit = new RecordingAuditLogger();

        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn(new InMemoryRepository([$this->account]));
        $em->method('flush')->willReturnCallback(function () {
            $this->flushes++;
        });
        $http = new MockHttpClient(function ($method, $url, $options) {
            parse_str((string)($options['body'] ?? ''), $body);
            $this->bodies[] = ['url' => $url] + $body;
            return array_shift($this->responses) ?? new MockResponse('{}', ['http_code' => 500]);
        });
        $settings = $this->settings();
        $oauth = new OAuthClient($http, $settings);
        $plugin = $this->createMock(PluginService::class);
        $plugin->method('getPublicUrl')->willReturn('https://antispam.example.pl');

        $controller = new OAuthController($em, $settings, $oauth, new OAuthTokenManager($oauth, $this->crypto), $plugin);
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturnCallback(fn() => $this->csrfValid);
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(fn($name, $params = []) => $name === 'antispam_oauth_callback' ? '/account/oauth/callback' : '/' . $name . ($params ? '?' . http_build_query($params) : ''));
        $this->stack = new RequestStack();
        $controller->setContainer(new ServiceLocator([
            'security.token_storage' => fn() => new TokenStorage(),
            'security.csrf.token_manager' => fn() => $csrf,
            'router' => fn() => $router,
            'request_stack' => fn() => $this->stack,
            AuditLogger::class => fn() => $this->audit,
        ]));
        return $controller;
    }

    private function request(array $query = [], string $method = 'GET'): Request
    {
        $request = $method === 'GET' ? new Request($query) : new Request([], $query, [], [], [], ['REQUEST_METHOD' => 'POST']);
        $request->setSession($this->session);
        $this->stack->push($request);
        return $request;
    }

    private function flashes(string $type): array
    {
        return $this->session->getFlashBag()->peek($type);
    }

    private function connect(): array
    {
        $controller = $this->controller();
        $response = $controller->connectAction(5, $this->request(['_token' => 'ok']));
        $this->assertInstanceOf(RedirectResponse::class, $response);
        parse_str((string)parse_url($response->getTargetUrl(), PHP_URL_QUERY), $q);
        return [$controller, $q];
    }

    public function testConnectRedirectsToTheProviderWithStateAndPkce()
    {
        [, $q] = $this->connect();
        $this->assertSame('https://antispam.example.pl/account/oauth/callback', $q['redirect_uri']);
        $pending = $this->session->get(OAuthController::SESSION_KEY);
        $this->assertArrayHasKey($q['state'], $pending);
        $entry = $pending[$q['state']];
        $this->assertSame(5, $entry['account_id']);
        $this->assertSame(rtrim(strtr(base64_encode(hash('sha256', $entry['verifier'], true)), '+/', '-_'), '='), $q['code_challenge']);
        $this->assertArrayNotHasKey('verifier', $q, 'the verifier never leaves the server');
    }

    public function testConnectNeedsTheCsrfToken()
    {
        $controller = $this->controller();
        $this->csrfValid = false;
        $this->expectException(AccessDeniedException::class);
        $controller->connectAction(5, $this->request(['_token' => 'bad']));
    }

    public function testCallbackWithUnknownStateIsRefused()
    {
        [$controller, $q] = $this->connect();
        $response = $controller->callbackAction($this->request(['state' => 'forged', 'code' => 'abc']));
        $this->assertStringContainsString('antispam_account_index', $response->getTargetUrl());
        $this->assertStringContainsString('state', $this->flashes('danger')[0]);
        $this->assertSame([], $this->bodies, 'no token request for a forged state');
        $this->assertArrayHasKey($q['state'], $this->session->get(OAuthController::SESSION_KEY), 'a forged state does not consume the real one');
    }

    public function testExpiredStateIsRefused()
    {
        [$controller, $q] = $this->connect();
        $pending = $this->session->get(OAuthController::SESSION_KEY);
        $pending[$q['state']]['created'] = time() - OAuthController::STATE_TTL - 1;
        $this->session->set(OAuthController::SESSION_KEY, $pending);
        $controller->callbackAction($this->request(['state' => $q['state'], 'code' => 'abc']));
        $this->assertStringContainsString('wygasły', $this->flashes('danger')[0]);
        $this->assertSame([], $this->bodies);
    }

    public function testProviderErrorIsShownAndStateConsumed()
    {
        [$controller, $q] = $this->connect();
        $controller->callbackAction($this->request(['state' => $q['state'], 'error' => 'access_denied', 'error_description' => "AADSTS65004: User declined to consent.\r\nTrace ID: x"]));
        $flash = $this->flashes('danger')[0];
        $this->assertStringContainsString('access_denied', $flash);
        $this->assertStringContainsString('AADSTS65004', $flash);
        $this->assertStringNotContainsString('Trace ID', $flash);
        $this->assertSame([], $this->session->get(OAuthController::SESSION_KEY), 'single use');
        $this->assertFalse($this->account->isOAuthConnected());
    }

    public function testSuccessfulCallbackStoresTokensAndAudits()
    {
        [$controller, $q] = $this->connect();
        $this->responses[] = new MockResponse(json_encode(['access_token' => 'AT', 'refresh_token' => 'RT', 'expires_in' => 3600, 'id_token' => self::idToken(['preferred_username' => 'jan@firma.pl'])]));
        $controller->callbackAction($this->request(['state' => $q['state'], 'code' => 'CODE']));

        $this->assertSame('CODE', $this->bodies[0]['code']);
        $this->assertTrue($this->account->isOAuthConnected());
        $this->assertSame('jan@firma.pl', $this->account->getOAuthUsername());
        $this->assertSame('RT', $this->crypto->decrypt($this->account->getOAuthRefreshToken()));
        $this->assertSame(1, $this->flushes);
        $this->assertSame('account.oauth_connected', $this->audit->entries[0]['action']);
        $this->assertStringNotContainsString('RT', json_encode($this->audit->entries[0]['details']));
        $this->assertStringContainsString('Połączono z Microsoft 365 jako jan@firma.pl', $this->flashes('success')[0]);

        // Replaying the same callback does nothing.
        $controller->callbackAction($this->request(['state' => $q['state'], 'code' => 'CODE']));
        $this->assertCount(1, $this->bodies);
    }

    public function testGoogleRefusesAnotherAccountThanTheLogin()
    {
        $account = $this->account(Account::AUTH_OAUTH_GOOGLE)->setImapLogin('jan@firma.pl');
        $controller = $this->controller($account);
        $response = $controller->connectAction(5, $this->request(['_token' => 'ok']));
        parse_str((string)parse_url($response->getTargetUrl(), PHP_URL_QUERY), $q);
        $this->responses[] = new MockResponse(json_encode(['access_token' => 'AT', 'refresh_token' => 'RT', 'expires_in' => 3600, 'id_token' => self::idToken(['email' => 'prywatne@gmail.com'])]));
        $controller->callbackAction($this->request(['state' => $q['state'], 'code' => 'CODE']));
        $this->assertStringContainsString('prywatne@gmail.com', $this->flashes('danger')[0]);
        $this->assertFalse($account->isOAuthConnected());
    }

    public function testDisconnectNeedsCsrfAndClearsTokens()
    {
        $account = $this->account(Account::AUTH_OAUTH_GOOGLE)->setOAuthRefreshToken('x')->setOAuthAccessToken('y');
        $controller = $this->controller($account);
        $this->csrfValid = false;
        try {
            $controller->disconnectAction(5, $this->request(['_token' => 'bad'], 'POST'));
            $this->fail('expected 403');
        } catch (AccessDeniedException) {
            $this->assertTrue($account->isOAuthConnected());
        }
        $this->csrfValid = true;
        $controller->disconnectAction(5, $this->request(['_token' => 'ok'], 'POST'));
        $this->assertFalse($account->isOAuthConnected());
        $this->assertNull($account->getOAuthAccessToken());
        $this->assertSame('account.oauth_disconnected', $this->audit->entries[0]['action']);
    }

    public function testAppOnlyAccountsDoNotStartAConsent()
    {
        $controller = $this->controller($this->account(Account::AUTH_OAUTH_MICROSOFT_APP));
        $response = $controller->connectAction(5, $this->request(['_token' => 'ok']));
        $this->assertStringContainsString('antispam_account_edit', $response->getTargetUrl());
        $this->assertNull($this->session->get(OAuthController::SESSION_KEY));
    }
}
