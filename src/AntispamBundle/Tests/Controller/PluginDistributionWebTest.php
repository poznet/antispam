<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\ThunderbirdPluginBuilder;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Plugin distribution in the panel (Ustawienia -> Wtyczki pocztowe): the
 * builds list, upload / removal of the generic Thunderbird package (POST +
 * CSRF) and the public /plugin/setup page. PluginService is mocked and the
 * upload goes to a temporary directory, so no database is needed.
 */
#[RequiresPhpExtension('zip')]
class PluginDistributionWebTest extends WebTestCase
{
    private string $storage;
    private ThunderbirdPluginBuilder $tb;
    private array $tmp = [];
    private string $hash;

    protected function setUp(): void
    {
        $this->storage = sys_get_temp_dir() . '/tbweb-' . bin2hex(random_bytes(4));
        $this->tb = new ThunderbirdPluginBuilder(null, $this->storage);
        // The env admin (ADMIN_USER / ADMIN_PASSWORD_HASH) - loginUser() must match the provider.
        $this->hash = password_hash('x', PASSWORD_BCRYPT, ['cost' => 4]);
        $_SERVER['ADMIN_PASSWORD_HASH'] = $_ENV['ADMIN_PASSWORD_HASH'] = $this->hash;
        $_SERVER['ADMIN_USER'] = $_ENV['ADMIN_USER'] = 'admin';
    }

    protected function tearDown(): void
    {
        unset($_SERVER['ADMIN_PASSWORD_HASH'], $_ENV['ADMIN_PASSWORD_HASH'], $_SERVER['ADMIN_USER'], $_ENV['ADMIN_USER']);
        $this->tb->removeUpload();
        @rmdir($this->storage);
        foreach ($this->tmp as $f) {
            @unlink($f);
        }
        parent::tearDown();
    }

    private function client(bool $admin = true): KernelBrowser
    {
        $client = static::createClient();
        $client->disableReboot();
        if ($admin) {
            $client->loginUser(new InMemoryUser('admin', $this->hash, ['ROLE_ADMIN']));
        }
        $plugin = $this->createMock(PluginService::class);
        $plugin->method('isEnabled')->willReturn(true);
        $plugin->method('isAnonymousReportEnabled')->willReturn(true);
        $plugin->method('isCheckEnabled')->willReturn(true);
        $plugin->method('isLearnRulesEnabled')->willReturn(true);
        $plugin->method('getTokenTtlDays')->willReturn(90);
        $plugin->method('getReportRateLimit')->willReturn(120);
        $plugin->method('getMaxUploadBytes')->willReturn(700 * 1024);
        $plugin->method('getPublicUrl')->willReturn('https://antispam.example.pl');
        static::getContainer()->set(PluginService::class, $plugin);
        static::getContainer()->set(ThunderbirdPluginBuilder::class, $this->tb);
        return $client;
    }

    /** CSRF tokens of the plugin page forms, by form action. */
    private function tokens(KernelBrowser $client): array
    {
        $crawler = $client->request('GET', '/config/plugin/');
        $this->assertResponseIsSuccessful();
        $tokens = [];
        foreach ($crawler->filterXPath('//form') as $form) {
            $tokens[$form->getAttribute('action')] = (new Crawler($form))->filterXPath('//input[@name="_token"]')->attr('value');
        }
        return $tokens;
    }

    private function xpi(bool $generic = true): UploadedFile
    {
        $path = tempnam(sys_get_temp_dir(), 'tbupl');
        $this->tmp[] = $path;
        $this->tb->build($generic ? null : 'https://evil.example', $path);
        return new UploadedFile($path, 'antispam-thunderbird.xpi', 'application/x-xpinstall', null, true);
    }

    public function testPageListsBuildsAndSetupLink()
    {
        $client = $this->client();
        $client->request('GET', '/config/plugin/');
        $this->assertResponseIsSuccessful();
        $html = (string)$client->getResponse()->getContent();
        $this->assertStringContainsString('build=instance', $html);
        $this->assertStringContainsString('build=generic', $html);
        $this->assertStringContainsString('/plugin/thunderbird/updates.json', $html);
        $this->assertStringContainsString('/plugin/setup', $html);
        $this->assertStringContainsString('wersję z adresem tego serwera', $html);
    }

    public function testUploadNeedsCsrfToken()
    {
        $client = $this->client();
        $client->request('POST', '/config/plugin/thunderbird-upload', ['_token' => 'bad'], ['xpi' => $this->xpi()]);
        $this->assertResponseRedirects('/config/plugin/');
        $this->assertNull($this->tb->uploadedBuild());
    }

    public function testUploadThenDownloadThenRemove()
    {
        $client = $this->client();
        $tokens = $this->tokens($client);

        $client->request('POST', '/config/plugin/thunderbird-upload', ['_token' => $tokens['/config/plugin/thunderbird-upload']], ['xpi' => $this->xpi()]);
        $this->assertResponseRedirects('/config/plugin/');
        $info = $this->tb->uploadedBuild();
        $this->assertNotNull($info);
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $info['version']);

        $client->request('GET', '/config/plugin/');
        $this->assertStringContainsString('wgraną wersję ogólną', (string)$client->getResponse()->getContent());

        $client->request('GET', '/plugin/download');
        $this->assertResponseIsSuccessful();
        $this->assertStringContainsString('antispam-thunderbird-' . PluginApiController::PLUGIN_VERSION . '.xpi', $client->getResponse()->headers->get('Content-Disposition'));

        $tokens = $this->tokens($client);
        $client->request('POST', '/config/plugin/thunderbird-upload/delete', ['_token' => $tokens['/config/plugin/thunderbird-upload/delete']]);
        $this->assertResponseRedirects('/config/plugin/');
        $this->assertNull($this->tb->uploadedBuild());
    }

    public function testUploadOfAnInstanceBuildIsRefused()
    {
        $client = $this->client();
        $tokens = $this->tokens($client);
        $client->request('POST', '/config/plugin/thunderbird-upload', ['_token' => $tokens['/config/plugin/thunderbird-upload']], ['xpi' => $this->xpi(false)]);
        $this->assertResponseRedirects('/config/plugin/');
        $this->assertNull($this->tb->uploadedBuild());
        $this->assertNotEmpty($client->getRequest()->getSession()->getFlashBag()->peek('danger'));
    }

    public function testUploadNeedsAdmin()
    {
        $client = $this->client(false);
        $client->request('POST', '/config/plugin/thunderbird-upload', ['_token' => 'x'], ['xpi' => $this->xpi()]);
        $this->assertTrue($client->getResponse()->isRedirect() || $client->getResponse()->getStatusCode() === 403);
        $this->assertNull($this->tb->uploadedBuild());
    }

    public function testSetupPageIsPublicAndShowsTheServer()
    {
        $client = $this->client(false);
        $client->request('GET', '/plugin/setup');
        $this->assertResponseIsSuccessful();
        $html = (string)$client->getResponse()->getContent();
        $this->assertStringContainsString('value="https://antispam.example.pl"', $html);
        $this->assertStringContainsString('/plugin/download?v=' . PluginApiController::PLUGIN_VERSION, $html);
    }
}
