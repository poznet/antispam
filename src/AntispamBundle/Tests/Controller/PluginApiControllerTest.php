<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\RawMessageScanner;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

class PluginApiControllerTest extends TestCase
{
    private const RAW = "From: Spammer <spam@evil.top>\r\nSubject: Buy now\r\n\r\nCheap pills\r\n";

    /** @var PluginService&MockObject */
    private $plugin;
    /** @var DeferredRetroactivePass&MockObject */
    private $deferred;
    /** @var EntityManagerInterface&MockObject */
    private $em;
    /** @var PhishingReportService&MockObject */
    private $phishing;
    /** @var string[] buckets passed to PluginService::hit() */
    private array $hits = [];

    protected function setUp(): void
    {
        $this->plugin = $this->createMock(PluginService::class);
        $this->plugin->method('isEnabled')->willReturn(true);
        $this->plugin->method('isAnonymousReportEnabled')->willReturn(true);
        $this->plugin->method('isCheckEnabled')->willReturn(true);
        $this->plugin->method('getReportRateLimit')->willReturn(120);
        $this->plugin->method('getMaxUploadBytes')->willReturn(700 * 1024);
        $this->plugin->method('hit')->willReturnCallback(function ($bucket) {
            $this->hits[] = $bucket;
            return true;
        });
        $this->deferred = $this->createMock(DeferredRetroactivePass::class);
        $this->em = $this->createMock(EntityManagerInterface::class);
        $this->phishing = $this->createMock(PhishingReportService::class);
    }

    private function controller(): PluginApiController
    {
        return new PluginApiController($this->createMock(RawMessageScanner::class), $this->plugin, $this->deferred, $this->em, $this->phishing);
    }

    private function post(array|string $body, string $token = ''): Request
    {
        $request = Request::create('/api/plugin/report', 'POST', [], [], [], ['REMOTE_ADDR' => '203.0.113.5'],
            is_string($body) ? $body : json_encode($body));
        if ($token !== '') {
            $request->headers->set('Authorization', 'Bearer ' . $token);
        }
        return $request;
    }

    private function loggedIn(): Account
    {
        $account = $this->createMock(Account::class);
        $account->method('getId')->willReturn(7);
        $account->method('getEmail')->willReturn('jan@example.com');
        $this->plugin->method('accountForToken')->willReturnCallback(fn ($t) => $t === 'good' ? $account : null);
        return $account;
    }

    public function testInvalidReportPayloadDoesNotUseTheRateLimit()
    {
        $this->plugin->expects($this->never())->method('learn');
        $c = $this->controller();

        $this->assertSame(400, $c->reportAction($this->post('not json'))->getStatusCode());
        $this->assertSame(400, $c->reportAction($this->post(['verdict' => 'spam', 'raw_base64' => '%%%']))->getStatusCode());
        $this->assertSame(400, $c->reportAction($this->post(['verdict' => 'maybe', 'raw_base64' => base64_encode(self::RAW)]))->getStatusCode());
        $this->assertSame(401, $c->reportAction($this->post(['verdict' => 'ham', 'raw_base64' => base64_encode(self::RAW)]))->getStatusCode());
        $this->assertSame([], $this->hits);
    }

    public function testValidAnonymousReportIsCountedAndHasNoRetroactivePass()
    {
        $this->plugin->method('learn')->willReturn(['verdict' => 'spam', 'sender' => 'spam@evil.top', 'signals' => 2, 'rules' => []]);
        $this->deferred->expects($this->never())->method('defer');

        $res = $this->controller()->reportAction($this->post(['verdict' => 'spam', 'raw_base64' => base64_encode(self::RAW)]));
        $data = json_decode($res->getContent(), true);

        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame(['report'], $this->hits);
        $this->assertFalse($data['authenticated']);
        $this->assertArrayNotHasKey('retroactive', $data);
    }

    public function testLoggedInReportDefersTheRetroactivePass()
    {
        $this->loggedIn();
        $this->plugin->method('learn')->willReturn([
            'verdict' => 'spam', 'sender' => 'spam@evil.top', 'signals' => 1, 'rules' => ['email_blacklist_added:spam@evil.top'],
        ]);
        $rule = (new EmailBlacklist())->setEmail('jan@example.com')->setBlacklistemail('spam@evil.top');
        $repo = $this->createMock(EntityRepository::class);
        $repo->method('findOneBy')->willReturn($rule);
        $this->em->method('getRepository')->with(EmailBlacklist::class)->willReturn($repo);
        $this->deferred->expects($this->once())->method('defer')->with($rule);

        $res = $this->controller()->reportAction($this->post(['verdict' => 'spam', 'raw_base64' => base64_encode(self::RAW)], 'good'));
        $data = json_decode($res->getContent(), true);

        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame('scheduled', $data['retroactive']);
        // Not known while answering any more - the pass runs after the response.
        $this->assertArrayNotHasKey('moved_existing', $data);
        $this->assertSame(['report', 'retro'], $this->hits);
    }

    public function testInvalidPhishingPayloadDoesNotUseTheRateLimits()
    {
        $this->loggedIn();
        $this->phishing->expects($this->never())->method('submit');
        $c = $this->controller();

        $this->assertSame(401, $c->phishingAction($this->post(['raw_base64' => base64_encode(self::RAW)]))->getStatusCode());
        $this->assertSame(400, $c->phishingAction($this->post(['raw_base64' => ''], 'good'))->getStatusCode());
        $this->assertSame(400, $c->phishingAction($this->post('{', 'good'))->getStatusCode());
        $tooBig = base64_encode(str_repeat('x', PhishingReportService::MAX_RAW_BYTES + 1));
        $this->assertSame(413, $c->phishingAction($this->post(['raw_base64' => $tooBig], 'good'))->getStatusCode());
        $this->assertSame([], $this->hits);
    }

    public function testValidPhishingReportCountsBothBudgets()
    {
        $this->loggedIn();
        $this->phishing->method('submit')->willReturn(['id' => 11, 'duplicate' => false]);
        $this->plugin->method('learn')->willReturn(['verdict' => 'spam', 'sender' => 'spam@evil.top', 'signals' => 0, 'rules' => []]);

        $res = $this->controller()->phishingAction($this->post(['raw_base64' => base64_encode(self::RAW), 'client' => 'thunderbird'], 'good'));

        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame(['phishing', 'report'], $this->hits);
        $this->assertSame(11, json_decode($res->getContent(), true)['phishing_id']);
    }

    public function testStatusPublishesTheUploadLimit()
    {
        $data = json_decode($this->controller()->statusAction(Request::create('/api/plugin/status'))->getContent(), true);

        $this->assertSame(700 * 1024, $data['max_upload_bytes']);
        $this->assertSame(PhishingReportService::MAX_RAW_BYTES, $data['phishing_max_bytes']);
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $data['version']);
        $this->assertFalse($data['authenticated']);
    }

    public function testManifestVersionMatchesPluginVersion()
    {
        $manifest = json_decode(file_get_contents(__DIR__ . '/../../Resources/thunderbird/manifest.json'), true);
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $manifest['version']);
        $this->assertTrue($manifest['options_ui']['open_in_tab']);
    }

    #[RequiresPhpExtension('zip')]
    public function testDownloadIsNeverCached()
    {
        $this->plugin->method('getPublicUrl')->willReturn('https://antispam.example.com');
        $res = $this->controller()->downloadAction(Request::create('/plugin/download'));

        $this->assertSame(200, $res->getStatusCode());
        $this->assertStringContainsString('no-store', $res->headers->get('Cache-Control'));
        $this->assertStringContainsString('private', $res->headers->get('Cache-Control'));
        $this->assertStringNotContainsString('public', $res->headers->get('Cache-Control'));

        $zip = new \ZipArchive();
        $this->assertTrue($zip->open($res->getFile()->getPathname()));
        $manifest = json_decode($zip->getFromName('manifest.json'), true);
        $config = json_decode($zip->getFromName('config.json'), true);
        $zip->close();
        @unlink($res->getFile()->getPathname());

        $this->assertSame('https://antispam.example.com', $config['server']);
        $this->assertContains('https://antispam.example.com/*', $manifest['permissions']);
        $this->assertSame(['none'], $manifest['browser_specific_settings']['gecko']['data_collection_permissions']['required']);
    }
}
