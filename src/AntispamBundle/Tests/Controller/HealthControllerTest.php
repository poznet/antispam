<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\HealthController;
use AntispamBundle\Services\HealthAlerter;
use AntispamBundle\Services\HealthDataSource;
use AntispamBundle\Services\HealthMetrics;
use AntispamBundle\Services\HealthService;
use AntispamBundle\Services\HealthSettings;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/**
 * /health (public minimal answer, token-protected details), /metrics and the
 * "Stan systemu" template. No database: the health service is mocked.
 */
class HealthControllerTest extends KernelTestCase
{
    private const TOKEN = 'abcdefghijklmnop0123';

    /** @var HealthService&MockObject */
    private $health;
    /** @var HealthSettings&MockObject */
    private $settings;

    private function controller(string $status = 'degraded'): HealthController
    {
        $this->health = $this->createMock(HealthService::class);
        $this->health->method('run')->willReturnCallback(fn(bool $full = false) => self::report($status, $full));
        $this->settings = $this->createMock(HealthSettings::class);
        $this->settings->method('isValidToken')->willReturnCallback(fn($t) => $t === self::TOKEN);
        $data = $this->createMock(HealthDataSource::class);
        $data->method('cronStatsSince')->willReturn([]);
        $data->method('decisionsSince')->willReturn([]);
        $data->method('quarantinedSince')->willReturn([]);

        return new HealthController($this->health, $this->settings, $this->createMock(HealthAlerter::class), new HealthMetrics($data), new ArrayAdapter());
    }

    private static function report(string $status, bool $full = false): array
    {
        return [
            'status' => $status,
            'checked_at' => '2026-10-28T12:00:00+00:00',
            'full' => $full,
            'checks' => [
                HealthService::check('db', 'system', 'Baza danych', 'ok', 'Połączenie działa', ['size_bytes' => 100], true),
                HealthService::check('account:1', 'accounts', 'secret-box@example.com', 'fail', 'Logowanie IMAP nieudane', ['type' => 'imap', 'last_scan_age_seconds' => 9000]),
                HealthService::check('clamav', 'services', 'ClamAV', 'skip', 'Wyłączony'),
            ],
        ];
    }

    public function testPublicHealthIsMinimal()
    {
        $response = $this->controller()->healthAction(Request::create('/health'));
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('{"status":"degraded"}', $response->getContent());
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
    }

    public function testPublicHealthFailIs503()
    {
        $response = $this->controller('fail')->healthAction(Request::create('/health'));
        $this->assertSame(503, $response->getStatusCode());
        $this->assertSame(['status' => 'fail'], json_decode($response->getContent(), true));
    }

    public function testPublicHealthIsCached()
    {
        $controller = $this->controller('ok');
        $this->health->expects($this->once())->method('run');
        $controller->healthAction(Request::create('/health'));
        $controller->healthAction(Request::create('/health'));
    }

    public function testTokenReturnsDetails()
    {
        $response = $this->controller()->healthAction(Request::create('/health', 'GET', ['token' => self::TOKEN]));
        $this->assertSame(200, $response->getStatusCode());
        $data = json_decode($response->getContent(), true);
        $this->assertSame('degraded', $data['status']);
        $this->assertFalse($data['full']);
        $this->assertSame('secret-box@example.com', $data['checks'][1]['label']);
    }

    public function testBearerTokenAndFullFlag()
    {
        $request = Request::create('/health', 'GET', ['full' => '1']);
        $request->headers->set('Authorization', 'Bearer ' . self::TOKEN);
        $data = json_decode($this->controller()->healthAction($request)->getContent(), true);
        $this->assertTrue($data['full']);
        $this->assertCount(3, $data['checks']);
    }

    public function testWrongTokenIsForbiddenAndLeaksNothing()
    {
        $controller = $this->controller();
        $this->health->expects($this->never())->method('run');
        $response = $controller->healthAction(Request::create('/health', 'GET', ['token' => 'wrong-token-wrong-token']));
        $this->assertSame(403, $response->getStatusCode());
        $this->assertStringNotContainsString('secret-box', $response->getContent());
    }

    public function testMetricsNeedToken()
    {
        $controller = $this->controller();
        $this->assertSame(403, $controller->metricsAction(Request::create('/metrics'))->getStatusCode());
        $this->assertSame(403, $controller->metricsAction(Request::create('/metrics', 'GET', ['token' => 'nope']))->getStatusCode());

        $response = $controller->metricsAction(Request::create('/metrics', 'GET', ['token' => self::TOKEN]));
        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringStartsWith('text/plain; version=0.0.4', $response->headers->get('Content-Type'));
        $this->assertStringContainsString('antispam_health_status 1', $response->getContent());
        $this->assertStringContainsString('antispam_account_last_scan_age_seconds{account="secret-box@example.com",type="imap"} 9000', $response->getContent());
    }

    public function testStateChangingRoutesArePostOnly()
    {
        self::bootKernel();
        $router = self::getContainer()->get('router');
        $router->getContext()->setMethod('GET');
        foreach (['/system/status/check', '/system/status/settings', '/system/status/test-alert'] as $path) {
            try {
                $router->match($path);
                $this->fail($path . ' must not match GET');
            } catch (\Symfony\Component\Routing\Exception\MethodNotAllowedException $e) {
                $this->assertSame(['POST'], $e->getAllowedMethods());
            }
        }
    }

    public function testStatusPageTemplateRenders()
    {
        self::bootKernel();
        $container = self::getContainer();
        $request = Request::create('/system/status');
        $request->attributes->set('_route', 'antispam_system_status');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $container->get(RequestStack::class)->push($request);

        $settings = $this->createMock(HealthSettings::class);
        $settings->method('getAlertEmails')->willReturn(['ops@example.com']);
        $settings->method('getEffectiveAlertEmails')->willReturn(['ops@example.com']);
        $settings->method('getFailThreshold')->willReturn(2);
        $settings->method('getScanMaxAge')->willReturn(60);
        $settings->method('getToken')->willReturn(self::TOKEN);
        $report = self::report('degraded', true);
        $groups = [];
        foreach ($report['checks'] as $check) {
            $groups[$check['group']][] = $check;
        }

        $html = $container->get('twig')->render('@Antispam/Health/index.html.twig', [
            'report' => $report,
            'groups' => $groups,
            'group_labels' => ['system' => 'System', 'accounts' => 'Konta pocztowe', 'services' => 'Usługi zewnętrzne'],
            'settings' => $settings,
            'alert_state' => [
                'checks' => ['account:1' => ['fails' => 3, 'alerted' => true, 'since' => '2026-10-28T11:00:00+00:00']],
                'last_run_at' => '2026-10-28T12:00:00+00:00',
                'last_errors' => ['Webhook: HTTP 500'],
            ],
            'has_channels' => true,
            'health_url' => 'https://antispam.example.com/health',
            'metrics_url' => 'https://antispam.example.com/metrics',
        ]);

        $this->assertStringContainsString('Częściowe problemy', $html);
        $this->assertStringContainsString('Logowanie IMAP nieudane', $html);
        $this->assertStringContainsString('3× z rzędu', $html);
        $this->assertStringContainsString('Webhook: HTTP 500', $html);
        $this->assertStringContainsString('value="' . self::TOKEN . '"', $html);
        $this->assertMatchesRegularExpression('/action="\/system\/status\/check"[^>]*>\s*<input type="hidden" name="_token" value="[^"]+"/', $html);
        $this->assertMatchesRegularExpression('/action="\/system\/status\/settings"[^>]*>\s*<input type="hidden" name="_token" value="[^"]+"/', $html);
        $this->assertStringContainsString('Stan systemu', $html);
    }
}
