<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\AppVersion;
use AntispamBundle\Controller\ChangelogController;
use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\RawMessageScanner;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * Release info: version in the panel footer (admins only, never on public
 * pages), server_version in /api/plugin/status, the "Co nowego" page.
 * No database needed.
 */
class ReleaseInfoTest extends WebTestCase
{
    private const ADMIN_HASH = 'test-admin-hash';

    protected function setUp(): void
    {
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

    /** Renders a template as the given roles (null = anonymous). */
    private function render(string $template, array $vars, ?array $roles): string
    {
        self::bootKernel();
        $c = self::getContainer();
        $request = Request::create('/panel');
        $request->attributes->set('_route', 'antispam_index');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $c->get('request_stack')->push($request);
        if ($roles !== null) {
            $user = new InMemoryUser('someone', 'x', $roles);
            $c->get('security.token_storage')->setToken(new UsernamePasswordToken($user, 'main', $roles));
        }

        return $c->get('twig')->render($template, $vars);
    }

    private function versionMarker(): string
    {
        return 'wersja ' . AppVersion::VERSION;
    }

    public function testFooterShowsVersionToAdmin()
    {
        $html = $this->render('@Antispam/Changelog/index.html.twig', [
            'version' => new AppVersion(sys_get_temp_dir()),
            'agent_version' => '3.0',
            'changelog_html' => '<p>x</p>',
        ], ['ROLE_ADMIN']);

        $this->assertMatchesRegularExpression('~<footer class="pp-footer">.*<a href="/changelog"[^>]*>' . preg_quote($this->versionMarker(), '~') . '~s', $html);
    }

    public function testFooterHidesVersionFromEndUsers()
    {
        $html = $this->render('@Antispam/Changelog/index.html.twig', [
            'version' => new AppVersion(sys_get_temp_dir()),
            'agent_version' => null,
            'changelog_html' => null,
        ], ['ROLE_USER']);

        $footer = substr($html, (int) strpos($html, '<footer class="pp-footer">'));
        $this->assertStringNotContainsString($this->versionMarker(), $footer);
        $this->assertStringNotContainsString('/changelog', $footer);
    }

    public function testPublicPagesDoNotShowTheVersion()
    {
        $client = static::createClient();
        $client->request('GET', '/');
        $this->assertResponseIsSuccessful();
        $this->assertStringNotContainsString(AppVersion::VERSION, (string) $client->getResponse()->getContent());

        self::ensureKernelShutdown();

        // The branded error page (prod) - the test env shows the debug page instead.
        $error = $this->render('@Twig/Exception/error.html.twig', ['status_code' => 500, 'status_text' => 'Internal Server Error'], null);
        $this->assertStringNotContainsString(AppVersion::VERSION, $error);
    }

    public function testPluginStatusHasServerVersion()
    {
        $plugin = $this->createMock(PluginService::class);
        $plugin->method('isEnabled')->willReturn(true);
        $controller = new PluginApiController(
            $this->createMock(RawMessageScanner::class),
            $plugin,
            $this->createMock(DeferredRetroactivePass::class),
            $this->createMock(EntityManagerInterface::class),
            $this->createMock(PhishingReportService::class),
        );

        $data = json_decode((string) $controller->statusAction(Request::create('/api/plugin/status'))->getContent(), true);
        $this->assertSame(AppVersion::VERSION, $data['server_version']);
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $data['version']);
    }

    public function testChangelogRequiresAdmin()
    {
        $attributes = (new \ReflectionClass(ChangelogController::class))->getAttributes(IsGranted::class);
        $this->assertCount(1, $attributes);
        $this->assertSame('ROLE_ADMIN', $attributes[0]->newInstance()->attribute);

        self::bootKernel();
        [$roles] = self::getContainer()->get('security.access_map')->getPatterns(Request::create('/changelog'));
        $this->assertSame(['ROLE_ADMIN'], $roles);
        self::ensureKernelShutdown();

        $client = static::createClient();
        $client->request('GET', '/changelog');
        $this->assertResponseRedirects();
        $this->assertStringContainsString('/login', (string) $client->getResponse()->headers->get('Location'));
    }

    public function testChangelogPageRendersEscapedChangelog()
    {
        $client = $this->adminClient();
        $client->request('GET', '/changelog');
        $this->assertResponseIsSuccessful();
        $html = (string) $client->getResponse()->getContent();

        $this->assertStringContainsString('<strong>' . AppVersion::VERSION . '</strong>', $html);
        $this->assertStringContainsString('<h3>Added</h3>', $html);
        $this->assertStringContainsString('<code>AntispamBundle\AppVersion::VERSION</code>', $html);
    }

    public function testChangelogPageEscapesHtmlFromTheFile()
    {
        $file = tempnam(sys_get_temp_dir(), 'changelog');
        file_put_contents($file, "# Changelog\n\n## [9.9.9]\n- <script>alert('x')</script> <img src=x onerror=alert(1)>\n");
        try {
            $this->render('@Antispam/Changelog/index.html.twig', ['version' => new AppVersion(sys_get_temp_dir()), 'agent_version' => null, 'changelog_html' => null], ['ROLE_ADMIN']);
            $controller = self::getContainer()->get(ChangelogController::class);
            (new \ReflectionProperty($controller, 'changelogFile'))->setValue($controller, $file);
            $html = (string) $controller->indexAction()->getContent();
        } finally {
            unlink($file);
        }

        $this->assertStringContainsString('&lt;script&gt;alert(&apos;x&apos;)&lt;/script&gt;', $html);
        $this->assertStringNotContainsString("<script>alert('x')", $html);
        $this->assertStringNotContainsString('<img src=x', $html);
    }
}
