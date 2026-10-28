<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\RawMessageScanner;
use AntispamBundle\Services\ThunderbirdPluginBuilder;
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

    private ?ThunderbirdPluginBuilder $tb = null;
    private ?string $tbStorage = null;

    protected function tearDown(): void
    {
        if ($this->tb) {
            $this->tb->removeUpload();
            @rmdir((string)$this->tbStorage);
        }
    }

    private function tb(): ThunderbirdPluginBuilder
    {
        if (!$this->tb) {
            $this->tbStorage = sys_get_temp_dir() . '/tbctl-' . bin2hex(random_bytes(4));
            $this->tb = new ThunderbirdPluginBuilder(null, $this->tbStorage);
        }
        return $this->tb;
    }

    private function controller(): PluginApiController
    {
        return new PluginApiController($this->createMock(RawMessageScanner::class), $this->plugin, $this->deferred, $this->em, $this->phishing, $this->tb());
    }

    /** @return array{manifest: array, config: array|null} of a downloaded .xpi (file deleted) */
    private function download(string $query = ''): array
    {
        $res = $this->controller()->downloadAction(Request::create('/plugin/download' . $query));
        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame('application/x-xpinstall', $res->headers->get('Content-Type'));
        $path = $res->getFile()->getPathname();
        $zip = new \ZipArchive();
        $this->assertTrue($zip->open($path));
        $out = [
            'manifest' => json_decode($zip->getFromName('manifest.json'), true),
            'config' => ($c = $zip->getFromName('config.json')) === false ? null : json_decode($c, true),
            'marker' => $zip->getFromName('uploaded-marker.txt'),
            'disposition' => $res->headers->get('Content-Disposition'),
        ];
        $zip->close();
        if (!str_starts_with($path, (string)$this->tbStorage)) {
            @unlink($path);
        }
        return $out;
    }

    /** Stores an "uploaded" generic package with a marker file. */
    private function upload(): void
    {
        $xpi = tempnam(sys_get_temp_dir(), 'tbup');
        $this->tb()->build(null, $xpi);
        $zip = new \ZipArchive();
        $zip->open($xpi);
        $zip->addFromString('uploaded-marker.txt', 'from ATN');
        $zip->close();
        $this->tb()->storeUpload($xpi, 'antispam.xpi');
        unlink($xpi);
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

    private function withAudit(PluginApiController $controller): \AntispamBundle\Tests\Support\RecordingAuditLogger
    {
        $audit = new \AntispamBundle\Tests\Support\RecordingAuditLogger();
        $controller->setContainer(new \Symfony\Component\DependencyInjection\ServiceLocator([
            \AntispamBundle\Services\AuditLogger::class => fn() => $audit,
        ]));
        return $audit;
    }

    /** Plugins before 1.3.0 send no scope: the token's mailbox learns, as before. */
    public function testReportWithoutScopeTeachesTheTokensMailbox()
    {
        $this->loggedIn();
        $this->plugin->expects($this->once())->method('learn')
            ->with($this->anything(), 'spam', $this->anything(), '203.0.113.5', 'plugin', PluginService::SCOPE_MAILBOX, null)
            ->willReturn(['verdict' => 'spam', 'sender' => 'spam@evil.top', 'signals' => 0, 'rules' => []]);
        $c = $this->controller();
        $audit = $this->withAudit($c);

        $data = json_decode($c->reportAction($this->post(['verdict' => 'spam', 'raw_base64' => base64_encode(self::RAW)], 'good'))->getContent(), true);

        $this->assertSame('jan@example.com', $data['mailbox']);
        $this->assertArrayNotHasKey('scope', $audit->entries[0]['details']);
        $this->assertArrayNotHasKey('reported_from', $audit->entries[0]['details']);
    }

    public function testReportOnlySpamLearnsNothingForTheMailboxAndHasNoRetroactivePass()
    {
        $this->loggedIn();
        $this->plugin->expects($this->once())->method('learn')
            ->with($this->anything(), 'spam', $this->anything(), $this->anything(), 'plugin', PluginService::SCOPE_REPORT_ONLY, 'anna@inna.pl')
            // Even if rules came back, a report_only report must not start a pass on the mailbox.
            ->willReturn(['verdict' => 'spam', 'sender' => 'spam@evil.top', 'signals' => 2, 'rules' => ['email_blacklist_added:spam@evil.top'], 'scope' => 'report_only']);
        $this->deferred->expects($this->never())->method('defer');
        $c = $this->controller();
        $audit = $this->withAudit($c);

        $res = $c->reportAction($this->post(['verdict' => 'spam', 'raw_base64' => base64_encode(self::RAW), 'scope' => 'report_only', 'reported_from' => 'Anna@Inna.pl'], 'good'));
        $data = json_decode($res->getContent(), true);

        $this->assertSame(200, $res->getStatusCode());
        $this->assertTrue($data['authenticated']);
        $this->assertNull($data['mailbox']);
        $this->assertArrayNotHasKey('retroactive', $data);
        $this->assertSame(['report'], $this->hits, 'counted against the authenticating account, no retro budget');
        $this->assertSame('jan@example.com', $audit->entries[0]['mailbox']);
        $this->assertSame('report_only', $audit->entries[0]['details']['scope']);
        $this->assertSame('anna@inna.pl', $audit->entries[0]['details']['reported_from']);
    }

    public function testReportOnlyNotSpamAndUnknownScopeAreRefused()
    {
        $this->loggedIn();
        $this->plugin->expects($this->never())->method('learn');
        $c = $this->controller();

        $ham = $c->reportAction($this->post(['verdict' => 'ham', 'raw_base64' => base64_encode(self::RAW), 'scope' => 'report_only'], 'good'));
        $this->assertSame(400, $ham->getStatusCode());
        $this->assertArrayHasKey('message', json_decode($ham->getContent(), true));
        $this->assertSame(400, $c->reportAction($this->post(['verdict' => 'spam', 'raw_base64' => base64_encode(self::RAW), 'scope' => 'all'], 'good'))->getStatusCode());
        $this->assertSame(400, $c->phishingAction($this->post(['raw_base64' => base64_encode(self::RAW), 'scope' => 'all'], 'good'))->getStatusCode());
        $this->assertSame([], $this->hits);
    }

    public function testAnonymousReportOnlySpamIsAccepted()
    {
        $this->plugin->method('learn')->willReturn(['verdict' => 'spam', 'sender' => 'spam@evil.top', 'signals' => 1, 'rules' => []]);

        $res = $this->controller()->reportAction($this->post(['verdict' => 'spam', 'raw_base64' => base64_encode(self::RAW), 'scope' => 'report_only', 'reported_from' => 'anna@inna.pl']));

        $this->assertSame(200, $res->getStatusCode());
        $this->assertFalse(json_decode($res->getContent(), true)['authenticated']);
    }

    public function testReportOnlyPhishingIsStoredWithTheForeignAddress()
    {
        $this->loggedIn();
        $this->phishing->expects($this->once())->method('submit')
            ->with($this->anything(), $this->anything(), 'thunderbird', '203.0.113.5', false, true, 'anna@inna.pl')
            ->willReturn(['id' => 12, 'duplicate' => false]);
        $this->plugin->expects($this->once())->method('learn')
            ->with($this->anything(), 'spam', $this->anything(), $this->anything(), 'phishing', PluginService::SCOPE_REPORT_ONLY, 'anna@inna.pl')
            ->willReturn(['verdict' => 'spam', 'sender' => 'spam@evil.top', 'signals' => 0, 'rules' => ['email_blacklist_added:spam@evil.top']]);
        $this->deferred->expects($this->never())->method('defer');
        $c = $this->controller();
        $audit = $this->withAudit($c);

        $res = $c->phishingAction($this->post(['raw_base64' => base64_encode(self::RAW), 'client' => 'thunderbird', 'scope' => 'report_only', 'reported_from' => ['anna@inna.pl']], 'good'));
        $data = json_decode($res->getContent(), true);

        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame(12, $data['phishing_id']);
        $this->assertNull($data['mailbox']);
        $this->assertSame(['phishing', 'report'], $this->hits);
        $this->assertSame('report_only', $audit->entries[0]['details']['scope']);
        $this->assertSame('anna@inna.pl', $audit->entries[0]['details']['reported_from']);
    }

    public function testOldPhishingRequestIsStoredAsTheMailboxsOwn()
    {
        $this->loggedIn();
        $this->phishing->expects($this->once())->method('submit')
            ->with($this->anything(), $this->anything(), 'outlook', $this->anything(), false, false, null)
            ->willReturn(['id' => 13, 'duplicate' => false]);
        $this->plugin->method('learn')->willReturn(['verdict' => 'spam', 'sender' => 'spam@evil.top', 'signals' => 0, 'rules' => []]);

        $data = json_decode($this->controller()->phishingAction($this->post(['raw_base64' => base64_encode(self::RAW), 'client' => 'outlook'], 'good'))->getContent(), true);

        $this->assertSame('jan@example.com', $data['mailbox']);
    }

    public function testStatusAdvertisesReportOnly()
    {
        $data = json_decode($this->controller()->statusAction(Request::create('/api/plugin/status'))->getContent(), true);

        $this->assertTrue($data['report_only']);
        $this->assertSame(['mailbox', 'report_only'], $data['report_scopes']);
    }

    public function testStatusPublishesTheUploadLimit()
    {
        $data = json_decode($this->controller()->statusAction(Request::create('/api/plugin/status'))->getContent(), true);

        $this->assertSame(700 * 1024, $data['max_upload_bytes']);
        $this->assertSame(PhishingReportService::MAX_RAW_BYTES, $data['phishing_max_bytes']);
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $data['version']);
        $this->assertFalse($data['authenticated']);
    }

    public function testPingAnswersAndIsWrittenToTheAuditLog()
    {
        $this->loggedIn();
        $audit = new \AntispamBundle\Tests\Support\RecordingAuditLogger();
        $controller = $this->controller();
        $controller->setContainer(new \Symfony\Component\DependencyInjection\ServiceLocator([
            \AntispamBundle\Services\AuditLogger::class => fn() => $audit,
        ]));

        $request = Request::create('/api/plugin/ping', 'POST', [], [], [], ['REMOTE_ADDR' => '203.0.113.5'],
            json_encode(['client' => 'thunderbird', 'client_version' => '1.1.3', 'app' => 'Thunderbird 153.6.0']));
        $request->headers->set('Authorization', 'Bearer good');
        $data = json_decode($controller->pingAction($request)->getContent(), true);

        $this->assertTrue($data['ok']);
        $this->assertTrue($data['authenticated']);
        $this->assertSame('jan@example.com', $data['email']);
        $this->assertSame('203.0.113.5', $data['client_ip']);
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $data['plugin_version']);
        $this->assertContains('ping', $this->hits);

        $this->assertCount(1, $audit->entries);
        $this->assertSame('plugin.ping', $audit->entries[0]['action']);
        $this->assertSame('jan@example.com', $audit->entries[0]['mailbox']);
        $this->assertSame('1.1.3', $audit->entries[0]['details']['client_version']);
    }

    public function testPingWithoutTokenIsAnonymousAndRateLimited()
    {
        $this->plugin = $this->createMock(PluginService::class);
        $this->plugin->method('hit')->willReturn(false);
        $res = $this->controller()->pingAction(Request::create('/api/plugin/ping', 'POST', [], [], [], [], '{}'));
        $this->assertSame(429, $res->getStatusCode());
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

    #[RequiresPhpExtension('zip')]
    public function testDownloadPrefersTheUploadedBuild()
    {
        $this->plugin->method('getPublicUrl')->willReturn('https://antispam.example.com');
        $this->assertNotFalse($this->download()['config'], 'instance build without an upload');

        $this->upload();
        $default = $this->download();
        $this->assertSame('from ATN', $default['marker']);
        $this->assertNull($default['config']);
        $this->assertStringContainsString('antispam-thunderbird-' . PluginApiController::PLUGIN_VERSION . '.xpi', $default['disposition']);

        // The update link of instance builds asks for the instance build explicitly.
        $instance = $this->download('?build=instance');
        $this->assertFalse($instance['marker']);
        $this->assertSame('https://antispam.example.com', $instance['config']['server']);
    }

    #[RequiresPhpExtension('zip')]
    public function testOutdatedUploadIsNotServed()
    {
        $this->plugin->method('getPublicUrl')->willReturn('https://antispam.example.com');
        $this->upload();
        $meta = $this->tbStorage . '/' . ThunderbirdPluginBuilder::UPLOAD_META;
        file_put_contents($meta, json_encode(['version' => '0.1'] + json_decode(file_get_contents($meta), true)));

        $res = $this->download();
        $this->assertFalse($res['marker']);
        $this->assertSame('https://antispam.example.com', $res['config']['server']);
    }

    #[RequiresPhpExtension('zip')]
    public function testGenericDownloadHasNoServer()
    {
        $this->plugin->method('getPublicUrl')->willReturn('https://antispam.example.com');
        $res = $this->download('?build=generic');
        $this->assertNull($res['config']);
        $this->assertArrayNotHasKey('update_url', $res['manifest']['browser_specific_settings']['gecko']);
        $this->assertNotContains('https://antispam.example.com/*', $res['manifest']['permissions']);
    }

    public function testUpdatesJsonListsTheCurrentVersion()
    {
        $this->plugin->method('getPublicUrl')->willReturn('https://antispam.example.com/');
        $res = $this->controller()->updatesAction(Request::create('/plugin/thunderbird/updates.json'));

        $this->assertSame(200, $res->getStatusCode());
        $this->assertStringContainsString('application/json', $res->headers->get('Content-Type'));
        $data = json_decode($res->getContent(), true);
        $update = $data['addons']['antispam@pancernapanda.pl']['updates'][0];
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $update['version']);
        $this->assertSame('https://antispam.example.com/plugin/download?build=instance&v=' . PluginApiController::PLUGIN_VERSION, $update['update_link']);
        $this->assertStringNotContainsString('\\/', $res->getContent(), 'readable URLs');
    }

    public function testUpdatesJsonIsGoneWhenPluginsAreDisabled()
    {
        $this->plugin = $this->createMock(PluginService::class);
        $this->plugin->method('isEnabled')->willReturn(false);
        $this->expectException(\Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class);
        $this->controller()->updatesAction(Request::create('/plugin/thunderbird/updates.json'));
    }
}
