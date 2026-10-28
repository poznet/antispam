<?php

namespace AntispamBundle\Tests\Security;

use AntispamBundle\Controller\AccountController;
use AntispamBundle\Controller\ConfigurationController;
use AntispamBundle\Controller\SpamboxController;
use AntispamBundle\EventListener\SecurityHeadersListener;
use AntispamBundle\Services\CryptoService;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\Exception\MethodNotAllowedException;
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * Web hardening (review batch 3): CSRF tokens on every POST form of the
 * settings / DNSBL / spam folder pages, state-changing routes POST only,
 * login throttling and the security headers. No database is needed: requests
 * are rejected before any query runs, templates are rendered with stub data.
 */
class WebHardeningTest extends WebTestCase
{
    private const ADMIN_HASH = 'test-admin-hash';

    protected function setUp(): void
    {
        // AdminUserProvider refuses to load the env admin without a hash; the
        // value is only compared, never verified, by loginUser().
        $_SERVER['ADMIN_PASSWORD_HASH'] = $_ENV['ADMIN_PASSWORD_HASH'] = self::ADMIN_HASH;
        $_SERVER['ADMIN_USER'] = $_ENV['ADMIN_USER'] = 'admin';
    }

    protected function tearDown(): void
    {
        unset($_SERVER['ADMIN_PASSWORD_HASH'], $_ENV['ADMIN_PASSWORD_HASH'], $_SERVER['ADMIN_USER'], $_ENV['ADMIN_USER']);
        parent::tearDown();
    }

    private function adminClient(): KernelBrowser
    {
        $client = static::createClient();
        $client->loginUser(new InMemoryUser('admin', self::ADMIN_HASH, ['ROLE_ADMIN']));

        return $client;
    }

    // ---- converted routes: POST only ---------------------------------------

    public static function postOnlyRoutes(): array
    {
        return [
            ['/dnsbl/add'],
            ['/dnsbl/add-preset/0'],
            ['/dnsbl/toggle/1'],
            ['/dnsbl/del/1'],
            ['/config/uncheck-all/'],
            ['/config/reset/countes/'],
            ['/config/spam/clamav-test/'],
            ['/config/spam/virustotal-test/'],
            ['/spambox/restore/SPAM/1'],
        ];
    }

    #[DataProvider('postOnlyRoutes')]
    public function testStateChangingRouteRejectsGet(string $path)
    {
        self::bootKernel();
        $router = self::getContainer()->get('router');
        $router->getContext()->setMethod('GET');
        try {
            $router->match($path);
            $this->fail($path . ' must not match GET');
        } catch (MethodNotAllowedException $e) {
            $this->assertSame(['POST'], $e->getAllowedMethods(), $path);
        }

        $router->getContext()->setMethod('POST');
        $this->assertArrayHasKey('_route', $router->match($path));
    }

    #[DataProvider('postOnlyRoutes')]
    public function testGetIsAnsweredWith405(string $path)
    {
        $client = $this->adminClient();
        $client->request('GET', $path);
        $this->assertSame(405, $client->getResponse()->getStatusCode(), $path);
    }

    // ---- controllers reject a missing / wrong CSRF token -------------------

    public static function tokenProtectedPosts(): array
    {
        return [
            'spam settings' => ['/config/spam/', '/config/spam/'],
            'feed settings' => ['/config/feed/', '/config/feed/'],
            'plugin settings' => ['/config/plugin/', '/config/plugin/'],
            'digest settings' => ['/config/digest/', '/config/digest/'],
            'uncheck all' => ['/config/uncheck-all/', '/config/spam/'],
            'reset counters' => ['/config/reset/countes/', '/config/spam/'],
            'clamav test' => ['/config/spam/clamav-test/', '/config/spam/'],
            'virustotal test' => ['/config/spam/virustotal-test/', '/config/spam/'],
            'dnsbl add' => ['/dnsbl/add', '/dnsbl/'],
            'dnsbl preset' => ['/dnsbl/add-preset/0', '/dnsbl/'],
            'dnsbl toggle' => ['/dnsbl/toggle/1', '/dnsbl/'],
            'dnsbl delete' => ['/dnsbl/del/1', '/dnsbl/'],
            'spam restore' => ['/spambox/restore/SPAM/1', '/spambox/index'],
        ];
    }

    #[DataProvider('tokenProtectedPosts')]
    public function testPostWithoutTokenIsRejected(string $path, string $redirect)
    {
        foreach ([[], ['_token' => 'forged']] as $body) {
            self::ensureKernelShutdown();
            $client = $this->adminClient();
            // Values that would change settings if the request got through
            // (and fail on the missing test database if anything was queried).
            $client->request('POST', $path, $body + ['config' => ['spam_threshold' => '1', 'public_url' => 'https://evil.example'], 'name' => 'x', 'zone' => 'evil.example']);

            $response = $client->getResponse();
            $this->assertTrue($response->isRedirect($redirect), $path . ' -> ' . $response->getStatusCode() . ' ' . $response->headers->get('Location'));
            $flashes = $client->getRequest()->getSession()->getFlashBag()->peek('danger');
            $this->assertNotEmpty($flashes, $path);
            $this->assertStringContainsString('token', $flashes[0]);
        }
    }

    public function testLegacyEmailSettingsRequireToken()
    {
        $client = $this->adminClient();
        $client->request('POST', '/config/email/', ['config' => ['password' => 'x']]);
        $this->assertSame(403, $client->getResponse()->getStatusCode());
    }

    // ---- every POST form of the touched templates carries a token ----------

    public static function templates(): array
    {
        $secret = ['set' => true, 'hint' => '…abcd'];

        return [
            ['@Antispam/Configuration/spamConfig.html.twig', 2, ['config' => [
                'vt_api_key' => $secret,
                'url' => ['gsb_api_key' => $secret],
                'impersonation_scores' => [],
                'attachment' => [],
            ]]],
            ['@Antispam/Configuration/feedConfig.html.twig', 1, ['config' => ['server_key' => $secret, 'remote_key' => $secret], 'stats' => []]],
            ['@Antispam/Configuration/pluginConfig.html.twig', 2, ['config' => [], 'base_url' => 'https://antispam.test', 'outlook_ok' => true, 'thunderbird_uploaded' => null, 'thunderbird_auto_update' => true]],
            // Settings + Thunderbird upload + removal of the uploaded package.
            ['@Antispam/Configuration/pluginConfig.html.twig', 3, ['config' => [], 'base_url' => 'https://antispam.test', 'outlook_ok' => true, 'thunderbird_auto_update' => true,
                'thunderbird_uploaded' => ['version' => '1.2.0', 'signed' => false, 'current' => true, 'uploaded_at' => '2026-10-28T12:00:00+01:00']]],
            ['@Antispam/Configuration/digestConfig.html.twig', 1, ['config' => [], 'errors' => [], 'mailboxes' => [['key' => 'imap', 'label' => 'IMAP', 'recipient' => 'a@b.pl', 'last_sent' => null]]]],
            ['@Antispam/Configuration/emailConfig.html.twig', 1, ['config' => ['password_set' => true, 'imap_flags' => '/imap/ssl'], 'imap_tls' => ['encryption' => 'ssl', 'validate_cert' => true]]],
            ['@Antispam/Dnsbl/index.html.twig', 4, [
                'providers' => [new class {
                    public $id = 7;
                    public $name = 'Evil';
                    public $zone = "x');alert(1);//";
                    public $score = 1;
                    public $cacheTtl = 60;
                    public $hits = 0;
                    public $enabled = true;
                }],
                'presets' => [['name' => 'Spamhaus ZEN', 'zone' => 'zen.spamhaus.org', 'score' => 8], ['name' => 'SpamCop', 'zone' => 'bl.spamcop.net', 'score' => 5]],
            ]],
            ['@Antispam/Spambox/index.html.twig', 2, [
                'messages' => [
                    ['id' => 1, 'from' => 'a@spam.test', 'subject' => 'One', 'date' => new \DateTime(), 'html' => '<img src="https://track.test/p.gif">', 'text' => null],
                    ['id' => 2, 'from' => 'b@spam.test', 'subject' => 'Two', 'date' => new \DateTime(), 'html' => null, 'text' => 'plain'],
                ],
                'selected' => ['id' => 2, 'from' => 'b@spam.test', 'subject' => 'Two'],
                'preview' => SpamboxController::previewDocument(null, 'plain <b>'),
            ]],
        ];
    }

    #[DataProvider('templates')]
    public function testEveryPostFormHasCsrfToken(string $template, int $expectedForms, array $context)
    {
        $html = $this->render($template, $context);

        $doc = new \DOMDocument();
        libxml_use_internal_errors(true);
        $doc->loadHTML('<?xml encoding="utf-8">' . $html);
        libxml_clear_errors();
        $xpath = new \DOMXPath($doc);

        $forms = $xpath->query('//form[translate(@method, "POST", "post")="post"]');
        $this->assertCount($expectedForms, $forms, $template);
        foreach ($forms as $form) {
            $token = $xpath->query('.//input[@type="hidden"][@name="_token"]', $form);
            $this->assertSame(1, $token->length, $template . ': form without _token');
            $this->assertGreaterThan(20, strlen($token->item(0)->getAttribute('value')), $template);
        }

        // Buttons submitting another form (form="..." attribute) must point at a form with a token.
        foreach ($xpath->query('//button[@form]') as $button) {
            $target = $xpath->query('//form[@id="' . $button->getAttribute('form') . '"]//input[@name="_token"]');
            $this->assertSame(1, $target->length, $template . ': button form=' . $button->getAttribute('form'));
        }

        // No inline event handlers (CSP-ready; DNSBL zone used to be injected into onclick).
        $this->assertSame(0, $xpath->query('//@*[starts-with(name(), "on")]')->length, $template . ': inline on* handler');
        // GET links must not point at the converted state-changing routes.
        foreach ($xpath->query('//a[@href]') as $a) {
            $this->assertDoesNotMatchRegularExpression('~/(dnsbl/(add|toggle|del)|config/(uncheck-all|reset|spam/clamav-test|spam/virustotal-test)|spambox/restore)~', $a->getAttribute('href'), $template);
        }
    }

    public function testStoredSecretsAreNotRenderedIntoForms()
    {
        $html = $this->render('@Antispam/Configuration/spamConfig.html.twig', ['config' => [
            'vt_api_key' => ConfigurationController::secretHint('vt-secret-0123456789-WXYZ'),
            'url' => ['gsb_api_key' => ConfigurationController::secretHint('gsb-secret-0123456789')],
            'impersonation_scores' => [],
            'attachment' => [],
        ]]);
        $this->assertStringNotContainsString('vt-secret', $html);
        $this->assertStringNotContainsString('gsb-secret', $html);
        $this->assertStringContainsString('(ustawione …WXYZ - zostaw puste, aby nie zmieniać)', $html);

        $html = $this->render('@Antispam/Configuration/feedConfig.html.twig', ['config' => [
            'server_key' => ConfigurationController::secretHint('server-key-secret-value'),
            'remote_key' => ConfigurationController::secretHint('short'),
        ], 'stats' => []]);
        $this->assertStringNotContainsString('server-key-secret', $html);
        $this->assertStringNotContainsString('value="short"', $html);

        $html = $this->render('@Antispam/Configuration/emailConfig.html.twig', ['config' => ['password_set' => true, 'imap_flags' => '/imap/ssl'], 'imap_tls' => ['encryption' => 'ssl', 'validate_cert' => true]]);
        $this->assertMatchesRegularExpression('~name="config\[password\]" value=""~', $html);
        $this->assertStringContainsString('zostaw puste, aby nie zmieniać', $html);
        // The connection check of the legacy page may use the stored password (stored host only).
        $this->assertStringContainsString('data-account-id="legacy"', $html);
    }

    public function testSecretHint()
    {
        $this->assertSame(['set' => false, 'hint' => ''], ConfigurationController::secretHint(null));
        $this->assertSame(['set' => true, 'hint' => ''], ConfigurationController::secretHint('short-key'));
        $this->assertSame(['set' => true, 'hint' => '…mnop'], ConfigurationController::secretHint('abcdefghijklmnop'));
    }

    public function testSpamPreviewDocumentBlocksRemoteContent()
    {
        $doc = SpamboxController::previewDocument('<html><head><title>x</title></head><body><img src="https://track.test/p.gif"></body></html>', null);
        $this->assertStringStartsWith('<meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:', $doc);
        $this->assertStringContainsString('<meta name="referrer" content="no-referrer">', $doc);

        $text = SpamboxController::previewDocument(null, '<script>alert(1)</script>');
        $this->assertStringContainsString('&lt;script&gt;', $text);
        $this->assertStringNotContainsString('<script>', $text);
    }

    public function testAccountValidation()
    {
        $this->assertSame([], AccountController::validateAccountData([
            'email' => 'jan@firma.pl', 'connection_type' => 'imap', 'imap_host' => 'mail.firma.pl', 'imap_port' => '993', 'imap_login' => 'jan@firma.pl',
        ]));
        $this->assertSame([], AccountController::validateAccountData([
            'email' => 'jan@firma.pl', 'connection_type' => 'ssh', 'ssh_host' => '10.0.0.5', 'ssh_port' => '22', 'ssh_user' => 'jan',
            'ssh_key_path' => 'jan_ed25519', 'maildir_path' => '~/Maildir', 'agent_path' => '~/antispam-agent',
        ]));
        $this->assertNotEmpty(AccountController::validateAccountData(['email' => 'x', 'connection_type' => 'imap', 'imap_host' => 'mail.firma.pl']));
        $this->assertNotEmpty(AccountController::validateAccountData(['email' => 'jan@firma.pl', 'connection_type' => 'imap', 'imap_host' => 'evil host/x']));
        $this->assertNotEmpty(AccountController::validateAccountData(['email' => 'jan@firma.pl', 'connection_type' => 'imap', 'imap_host' => 'mail.firma.pl', 'imap_port' => '70000']));
        $this->assertNotEmpty(AccountController::validateAccountData(['email' => 'jan@firma.pl', 'connection_type' => 'ftp']));
        $this->assertNotEmpty(AccountController::validateAccountData([
            'email' => 'jan@firma.pl', 'connection_type' => 'ssh', 'ssh_host' => 'h.pl', 'ssh_user' => 'jan;rm', 'maildir_path' => "~/Maildir\nrm -rf",
        ]));
    }

    public function testLegacyPasswordStaysReadable()
    {
        self::bootKernel();
        $crypto = self::getContainer()->get(CryptoService::class);
        $this->assertSame('plain-legacy', $crypto->decrypt('plain-legacy'));
        $this->assertSame('new-secret', $crypto->decrypt($crypto->encrypt('new-secret')));
        $this->assertLessThanOrEqual(255, strlen($crypto->encrypt(str_repeat('x', 128))), 'fits config.value VARCHAR(255)');
    }

    // ---- login throttling ---------------------------------------------------

    public function testLoginIsThrottled()
    {
        $client = static::createClient();
        $client->disableReboot();
        self::getContainer()->get('cache.rate_limiter')->clear();

        $error = null;
        for ($i = 0; $i < 6; $i++) {
            $client->request('POST', '/login', ['_username' => 'admin', '_password' => 'wrong-' . $i]);
            $this->assertTrue($client->getResponse()->isRedirect(), 'failed login redirects back to the form');
            $error = $client->getRequest()->getSession()->get(SecurityRequestAttributes::AUTHENTICATION_ERROR);
        }
        $this->assertInstanceOf(TooManyLoginAttemptsAuthenticationException::class, $error);
    }

    // ---- security headers -----------------------------------------------------

    public function testHomeAndErrorPagesSendSecurityHeaders()
    {
        $client = static::createClient();
        foreach (['/' => 200, '/no-such-page' => 404] as $path => $status) {
            $client->request('GET', $path);
            $response = $client->getResponse();
            $this->assertSame($status, $response->getStatusCode(), $path);
            if ($status === 200) {
                // In debug mode Symfony's ErrorListener drops the CSP of error
                // pages (for its exception page); prod keeps it.
                $this->assertSame(SecurityHeadersListener::POLICY_DEFAULT, $response->headers->get('Content-Security-Policy'), $path);
            }
            $this->assertSame('DENY', $response->headers->get('X-Frame-Options'), $path);
            $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'), $path);
            $this->assertSame('same-origin', $response->headers->get('Referrer-Policy'), $path);
            $this->assertFalse($response->headers->has('Strict-Transport-Security'), 'no HSTS outside prod');
        }
    }

    public function testSessionCookieIsSecureInProd()
    {
        $config = \Symfony\Component\Yaml\Yaml::parseFile(dirname(__DIR__, 4) . '/config/packages/framework.yaml');
        $this->assertTrue($config['when@prod']['framework']['session']['cookie_secure']);
        $this->assertSame('auto', $config['framework']['session']['cookie_secure'], 'dev over http keeps working');
    }

    public static function headerCases(): array
    {
        return [
            'panel' => ['/config/spam/', 'text/html; charset=UTF-8', SecurityHeadersListener::POLICY_DEFAULT, 'DENY'],
            'user area' => ['/my/quarantine', '', SecurityHeadersListener::POLICY_DEFAULT, 'DENY'],
            'digest action' => ['/q/abc.def', 'text/html; charset=UTF-8', SecurityHeadersListener::POLICY_DIGEST, 'DENY'],
            'outlook task pane' => ['/plugin/outlook/taskpane.html', 'text/html', null, null],
            'outlook manifest' => ['/plugin/outlook/manifest.xml', 'application/xml', null, null],
            'json api' => ['/api/plugin/status', 'application/json', null, 'DENY'],
        ];
    }

    #[DataProvider('headerCases')]
    public function testHeadersPerRoute(string $path, string $type, ?string $csp, ?string $frame)
    {
        $response = new Response('', 200, $type !== '' ? ['Content-Type' => $type] : []);
        foreach (['http://antispam.test', 'https://antispam.test'] as $base) {
            $headers = SecurityHeadersListener::headersFor(Request::create($base . $path), $response, 'prod');
            $this->assertSame($csp, $headers['Content-Security-Policy'] ?? null, $path);
            $this->assertSame($frame, $headers['X-Frame-Options'] ?? null, $path);
            $this->assertSame('nosniff', $headers['X-Content-Type-Options']);
            $this->assertSame(str_starts_with($base, 'https') ? SecurityHeadersListener::HSTS : null, $headers['Strict-Transport-Security'] ?? null, $base . $path);
        }
        $this->assertArrayNotHasKey('Strict-Transport-Security', SecurityHeadersListener::headersFor(Request::create('https://antispam.test' . $path), $response, 'dev'));
    }

    public function testControllerHeadersAreKept()
    {
        $client = static::createClient();
        $client->request('GET', '/q/abc.def');
        $response = $client->getResponse();
        // QuarantineActionController sets a stricter Referrer-Policy itself.
        $this->assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
        $this->assertSame(SecurityHeadersListener::POLICY_DIGEST, $response->headers->get('Content-Security-Policy'));
    }

    private function render(string $template, array $context): string
    {
        self::ensureKernelShutdown();
        self::bootKernel();
        $container = self::getContainer();
        $request = Request::create('/');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $container->get('request_stack')->push($request);

        $twig = $container->get('twig');
        // Stub contexts carry only what the assertions need.
        $twig->disableStrictVariables();

        return $twig->render($template, $context);
    }
}
