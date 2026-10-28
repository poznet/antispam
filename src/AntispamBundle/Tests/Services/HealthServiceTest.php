<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\CronRun;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ClamavService;
use AntispamBundle\Services\HealthDataSource;
use AntispamBundle\Services\HealthService;
use AntispamBundle\Services\HealthSettings;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SpamSignalService;
use AntispamBundle\Services\SshService;
use Ddeboer\Imap\ConnectionInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/** Every health check with mocked sources: ok / warn / fail / skip. */
class HealthServiceTest extends TestCase
{
    private const NOW = '2026-10-28 12:00:00';

    /** @var HealthDataSource&MockObject */
    private $data;
    /** @var HealthSettings&MockObject */
    private $settings;
    /** @var ScoringService&MockObject */
    private $scoring;
    /** @var ClamavService&MockObject */
    private $clamav;
    /** @var CertHoleService&MockObject */
    private $cert;
    /** @var SpamSignalService&MockObject */
    private $feed;
    /** @var SshService&MockObject */
    private $ssh;
    /** @var ImapScanService&MockObject */
    private $imap;

    /** @var array<string, CronRun[]> */
    private array $cron = [];
    private array $accounts = [];

    protected function setUp(): void
    {
        $this->data = $this->createMock(HealthDataSource::class);
        $this->settings = $this->createMock(HealthSettings::class);
        $this->settings->method('getScanMaxAge')->willReturn(60);
        $this->scoring = $this->createMock(ScoringService::class);
        $this->clamav = $this->createMock(ClamavService::class);
        $this->cert = $this->createMock(CertHoleService::class);
        $this->feed = $this->createMock(SpamSignalService::class);
        $this->ssh = $this->createMock(SshService::class);
        $this->imap = $this->createMock(ImapScanService::class);

        $this->data->method('accounts')->willReturnCallback(fn() => $this->accounts);
        $this->data->method('recentCronRuns')->willReturnCallback(fn($cmd) => $this->cron[$cmd] ?? []);
        $this->data->method('lastCronRuns')->willReturnCallback(function () {
            $out = [];
            foreach ($this->cron as $cmd => $runs) {
                if ($runs) {
                    $out[$cmd] = $runs[0];
                }
            }
            return $out;
        });
        $this->data->method('diskSpace')->willReturn(['free' => 50 * 1024 ** 3, 'total' => 100 * 1024 ** 3, 'path' => '/var']);
        $this->data->method('databaseSize')->willReturn(12345678);
    }

    private function service(): HealthService
    {
        $s = new HealthService($this->data, $this->settings, $this->scoring, $this->clamav, $this->cert, $this->feed, $this->ssh, $this->imap);
        $s->setNow(new \DateTimeImmutable(self::NOW));
        return $s;
    }

    private function check(array $report, string $key): array
    {
        foreach ($report['checks'] as $check) {
            if ($check['key'] === $key) {
                return $check;
            }
        }
        $this->fail('check ' . $key . ' missing');
    }

    /** CronRun started $minutesAgo before NOW, finished with $exit (null = still running). */
    public static function cronRun(string $cmd, int $minutesAgo, ?int $exit = 0): CronRun
    {
        $run = new CronRun($cmd);
        $r = new \ReflectionProperty(CronRun::class, 'startedAt');
        $r->setValue($run, new \DateTime(self::NOW . ' -' . $minutesAgo . ' minutes'));
        if ($exit !== null) {
            $run->finish($exit, '');
        }
        return $run;
    }

    /** Runs of $cmd every $every minutes, newest $first minutes ago. */
    private function schedule(string $cmd, int $first, int $every, int $count = 5, int $exit = 0): void
    {
        $this->cron[$cmd] = [];
        for ($i = 0; $i < $count; $i++) {
            $this->cron[$cmd][] = self::cronRun($cmd, $first + $i * $every, $exit);
        }
    }

    private function account(int $id, string $type, ?int $scannedMinutesAgo, array $result = [], bool $deployed = true): Account
    {
        $a = (new Account())->setName('A' . $id)->setEmail('box' . $id . '@example.com')->setConnectionType($type)->setAgentDeployed($deployed);
        (new \ReflectionProperty(Account::class, 'id'))->setValue($a, $id);
        if ($scannedMinutesAgo !== null) {
            $a->setLastScanAt(new \DateTime(self::NOW . ' -' . $scannedMinutesAgo . ' minutes'));
            $a->setLastScanResult(json_encode($result));
        }
        return $a;
    }

    // ---- database --------------------------------------------------------------

    public function testDatabaseOk()
    {
        $report = $this->service()->run();
        $db = $this->check($report, 'db');
        $this->assertSame('ok', $db['status']);
        $this->assertTrue($db['critical']);
        $this->assertSame(12345678, $db['details']['size_bytes']);
    }

    public function testDatabaseDownFailsOverallAndSkipsDbChecks()
    {
        $this->data->method('pingDatabase')->willThrowException(new \RuntimeException('Connection refused'));
        $this->data->expects($this->never())->method('accounts');
        $report = $this->service()->run();
        $this->assertSame('fail', $report['status']);
        $this->assertSame('fail', $this->check($report, 'db')['status']);
        $this->assertStringContainsString('Connection refused', $this->check($report, 'db')['message']);
        $this->assertSame(['db', 'disk', 'versions'], array_column($report['checks'], 'key'));
    }

    // ---- scheduler / cron jobs ---------------------------------------------------

    public function testSchedulerWithoutCronLogWarns()
    {
        $report = $this->service()->run();
        $this->assertSame('warn', $this->check($report, 'scheduler')['status']);
        $this->assertSame('skip', $this->check($report, 'cron:antispam:agent:scan-all')['status']);
        $this->assertSame('degraded', $report['status']);
    }

    public function testSchedulerAliveAndJobsOnTime()
    {
        $this->schedule('antispam:agent:scan-all', 2, 5);
        $this->schedule('antispam:digest:send', 300, 1440);
        $report = $this->service()->run();
        $this->assertSame('ok', $this->check($report, 'scheduler')['status']);
        $scan = $this->check($report, 'cron:antispam:agent:scan-all');
        $this->assertSame('ok', $scan['status']);
        $this->assertSame(5, $scan['details']['interval_minutes']);
        $this->assertSame('ok', $this->check($report, 'cron:antispam:digest:send')['status']);
        $this->assertSame('ok', $report['status']);
    }

    public function testStoppedSchedulerFailsOverall()
    {
        $this->schedule('antispam:agent:scan-all', 120, 5);
        $report = $this->service()->run();
        $this->assertSame('fail', $this->check($report, 'scheduler')['status']);
        $this->assertSame('fail', $this->check($report, 'cron:antispam:agent:scan-all')['status']);
        $this->assertSame('fail', $report['status']);
    }

    public function testIntervalIsInferredFromHistory()
    {
        // SCAN_INTERVAL=30: 40 minutes since the last run is fine, not late.
        $this->schedule('antispam:agent:scan-all', 40, 30);
        $scan = $this->check($this->service()->run(), 'cron:antispam:agent:scan-all');
        $this->assertSame(30, $scan['details']['interval_minutes']);
        $this->assertSame('ok', $scan['status']);
    }

    public function testLateJobWarns()
    {
        // default interval (5 min, single run): 20 min late > 2x+5, < 4x+15
        $this->cron['antispam:agent:scan-all'] = [self::cronRun('antispam:agent:scan-all', 20)];
        $this->assertSame('warn', $this->check($this->service()->run(), 'cron:antispam:agent:scan-all')['status']);
    }

    public function testFailedJobWarnsThenFailsAfterThreeInARow()
    {
        $this->cron['antispam:feed:sync'] = [self::cronRun('antispam:feed:sync', 1, 1), self::cronRun('antispam:feed:sync', 16, 0), self::cronRun('antispam:feed:sync', 31, 0)];
        $job = $this->check($this->service()->run(), 'cron:antispam:feed:sync');
        $this->assertSame('warn', $job['status']);
        $this->assertSame(1, $job['details']['consecutive_failures']);

        $this->schedule('antispam:feed:sync', 1, 15, 4, 1);
        $job = $this->check($this->service()->run(), 'cron:antispam:feed:sync');
        $this->assertSame('fail', $job['status']);
        $this->assertStringContainsString('kod 1', $job['message']);
    }

    public function testHungRunWarns()
    {
        $this->cron['antispam:cert:sync'] = [self::cronRun('antispam:cert:sync', 1000, null), self::cronRun('antispam:cert:sync', 1360)];
        $job = $this->check($this->service()->run(), 'cron:antispam:cert:sync');
        $this->assertSame('warn', $job['status']);
        $this->assertStringContainsString('nie zakończyło', $job['message']);
    }

    // ---- accounts ------------------------------------------------------------------

    public function testAccountRecentlyScannedIsOk()
    {
        $this->accounts = [$this->account(1, Account::CONNECTION_IMAP, 3)];
        $check = $this->check($this->service()->run(), 'account:1');
        $this->assertSame('ok', $check['status']);
        $this->assertSame('box1@example.com', $check['label']);
        $this->assertSame(180, $check['details']['last_scan_age_seconds']);
    }

    public function testStaleAccountFails()
    {
        $this->accounts = [$this->account(1, Account::CONNECTION_IMAP, 90)];
        $report = $this->service()->run();
        $this->assertSame('fail', $this->check($report, 'account:1')['status']);
        // a single mailbox is not an outage of the whole service
        $this->assertSame('degraded', $report['status']);
    }

    public function testNeverScannedOrUndeployedAccountWarns()
    {
        $this->accounts = [
            $this->account(1, Account::CONNECTION_IMAP, null),
            $this->account(2, Account::CONNECTION_SSH, null, [], false),
        ];
        $report = $this->service()->run();
        $this->assertSame('warn', $this->check($report, 'account:1')['status']);
        $this->assertSame('warn', $this->check($report, 'account:2')['status']);
        $this->assertStringContainsString('nie jest wdrożony', $this->check($report, 'account:2')['message']);
    }

    public function testScanErrorsAndOutdatedAgentWarn()
    {
        $this->accounts = [
            $this->account(1, Account::CONNECTION_IMAP, 2, ['errors' => ['Message 5: parse error']]),
            $this->account(2, Account::CONNECTION_SSH, 2, ['agent_warning' => 'Agent na serwerze jest w starszej wersji']),
        ];
        $report = $this->service()->run();
        $this->assertSame('warn', $this->check($report, 'account:1')['status']);
        $this->assertStringContainsString('parse error', $this->check($report, 'account:1')['message']);
        $this->assertSame('warn', $this->check($report, 'account:2')['status']);
    }

    public function testQuickCheckDoesNotTouchMailServers()
    {
        $this->accounts = [$this->account(1, Account::CONNECTION_IMAP, 2), $this->account(2, Account::CONNECTION_SSH, 2)];
        $this->imap->expects($this->never())->method('connect');
        $this->ssh->expects($this->never())->method('runHealth');
        $this->data->expects($this->never())->method('pendingSchemaChanges');
        $this->service()->run(false);
    }

    public function testFullCheckImapLogin()
    {
        $this->accounts = [$this->account(1, Account::CONNECTION_IMAP, 2), $this->account(2, Account::CONNECTION_IMAP, 2)];
        $conn = $this->createMock(ConnectionInterface::class);
        $conn->expects($this->once())->method('close');
        $this->imap->method('connect')->willReturnCallback(function (Account $a) use ($conn) {
            if ($a->getId() === 2) {
                throw new \RuntimeException('Authentication failed');
            }
            return $conn;
        });
        $report = $this->service()->run(true);
        $this->assertSame('ok', $this->check($report, 'account:1')['status']);
        $this->assertTrue($this->check($report, 'account:1')['details']['imap_login']);
        $this->assertSame('fail', $this->check($report, 'account:2')['status']);
        $this->assertStringContainsString('Authentication failed', $this->check($report, 'account:2')['message']);
    }

    public function testFullCheckSshAgent()
    {
        $this->accounts = [$this->account(1, Account::CONNECTION_SSH, 2), $this->account(2, Account::CONNECTION_SSH, 2), $this->account(3, Account::CONNECTION_SSH, 2)];
        $this->ssh->method('runHealth')->willReturnCallback(fn(Account $a) => match ($a->getId()) {
            1 => ['success' => true, 'agent_version' => '3.9', 'php' => '8.1.2', 'rules' => ['last_scan' => '2026-10-28T11:58:00+00:00']],
            2 => ['success' => true, 'agent_version' => '3.0', 'agent_outdated' => true, 'agent_warning' => 'Agent w starszej wersji'],
            3 => throw new \RuntimeException('SSH connection to host:22 failed'),
        });
        $report = $this->service()->run(true);
        $one = $this->check($report, 'account:1');
        $this->assertSame('ok', $one['status']);
        $this->assertSame('3.9', $one['details']['agent_version']);
        $this->assertSame('warn', $this->check($report, 'account:2')['status']);
        $this->assertSame('fail', $this->check($report, 'account:3')['status']);
    }

    public function testFullCheckAgentErrorAnswerFails()
    {
        $this->accounts = [$this->account(1, Account::CONNECTION_SSH, 2)];
        $this->ssh->method('runHealth')->willReturn(['success' => false, 'error' => 'Nie znaleziono agenta na serwerze']);
        $check = $this->check($this->service()->run(true), 'account:1');
        $this->assertSame('fail', $check['status']);
        $this->assertStringContainsString('Nie znaleziono agenta', $check['message']);
    }

    // ---- services --------------------------------------------------------------------

    public function testClamavSkippedWhenDisabled()
    {
        $this->scoring->method('isScoringEnabled')->willReturn(true);
        $this->scoring->method('isClamavEnabled')->willReturn(false);
        $this->clamav->expects($this->never())->method('ping');
        $this->assertSame('skip', $this->check($this->service()->run(), 'clamav')['status']);
    }

    public function testClamavPingOkAndFail()
    {
        $this->scoring->method('isScoringEnabled')->willReturn(true);
        $this->scoring->method('isClamavEnabled')->willReturn(true);
        $this->scoring->method('getClamavDsn')->willReturn('tcp://clamav:3310');
        $this->clamav->method('ping')->willReturnOnConsecutiveCalls(true, false);
        $this->assertSame('ok', $this->check($this->service()->run(), 'clamav')['status']);
        $report = $this->service()->run();
        $this->assertSame('fail', $this->check($report, 'clamav')['status']);
        $this->assertSame('degraded', $report['status']);
    }

    public static function certCases(): array
    {
        return [
            'disabled' => [false, null, null, '', 'skip'],
            'never synced' => [true, null, null, 'timeout', 'fail'],
            'fresh' => [true, '-2 hours', '-2 hours', '', 'ok'],
            'last attempt failed' => [true, '-3 hours', '-1 hour', 'HTTP 500', 'warn'],
            'old' => [true, '-30 hours', '-30 hours', '', 'warn'],
            'stale' => [true, '-4 days', '-1 hour', 'HTTP 500', 'fail'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('certCases')]
    public function testCert(bool $enabled, ?string $sync, ?string $attempt, string $error, string $expected)
    {
        $this->cert->method('isEnabled')->willReturn($enabled);
        $at = fn($rel) => $rel ? (new \DateTimeImmutable(self::NOW . ' ' . $rel))->format(DATE_ATOM) : null;
        $this->cert->method('getStatus')->willReturn(['last_sync_at' => $at($sync), 'last_attempt_at' => $at($attempt), 'count' => 1500, 'last_error' => $error]);
        $this->assertSame($expected, $this->check($this->service()->run(), 'cert')['status']);
    }

    public static function feedCases(): array
    {
        return [
            'disabled' => [false, 'https://hub', null, 'skip'],
            'hub mode' => [true, '', null, 'skip'],
            'never synced' => [true, 'https://hub', null, 'warn'],
            'fresh' => [true, 'https://hub', 10, 'ok'],
            'late' => [true, 'https://hub', 180, 'warn'],
            'stale' => [true, 'https://hub', 60 * 30, 'fail'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('feedCases')]
    public function testFeed(bool $enabled, string $url, ?int $minutesAgo, string $expected)
    {
        $this->feed->method('isEnabled')->willReturn($enabled);
        $this->feed->method('getRemoteUrl')->willReturn($url);
        $this->data->method('lastSuccessfulCronRun')->with('antispam:feed:sync')
            ->willReturn($minutesAgo === null ? null : self::cronRun('antispam:feed:sync', $minutesAgo));
        $this->assertSame($expected, $this->check($this->service()->run(), 'feed')['status']);
    }

    // ---- system ----------------------------------------------------------------------

    public static function diskCases(): array
    {
        $gb = 1024 ** 3;
        return [
            'plenty' => [50 * $gb, 100 * $gb, 'ok'],
            'below 2 GB' => [1 * $gb, 100 * $gb, 'warn'],
            'below 5%' => [3 * $gb, 100 * $gb, 'warn'],
            'below 500 MB' => [100 * 1024 ** 2, 100 * $gb, 'fail'],
            'unknown' => [null, null, 'skip'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('diskCases')]
    public function testDisk(?int $free, ?int $total, string $expected)
    {
        $data = $this->createMock(HealthDataSource::class);
        $data->method('diskSpace')->willReturn(['free' => $free, 'total' => $total, 'path' => '/var']);
        $data->method('accounts')->willReturn([]);
        $this->data = $data;
        $this->assertSame($expected, $this->check($this->service()->run(), 'disk')['status']);
    }

    public function testSchemaDriftOnlyInFullCheck()
    {
        $this->data->method('pendingSchemaChanges')->willReturn(['ALTER TABLE x ADD y INT']);
        $this->assertNotContains('schema', array_column($this->service()->run(false)['checks'], 'key'));
        $schema = $this->check($this->service()->run(true), 'schema');
        $this->assertSame('warn', $schema['status']);
        $this->assertSame(1, $schema['details']['pending']);
    }

    public function testVersionsReportPluginVersion()
    {
        $versions = $this->check($this->service()->run(), 'versions');
        $this->assertSame('ok', $versions['status']);
        $this->assertSame(\AntispamBundle\Controller\PluginApiController::PLUGIN_VERSION, $versions['details']['plugin']);
        $this->assertSame(PHP_VERSION, $versions['details']['php']);
    }

    public function testCheckThrowingBecomesFailure()
    {
        $this->cert->method('isEnabled')->willThrowException(new \LogicException('boom'));
        $cert = $this->check($this->service()->run(), 'cert');
        $this->assertSame('fail', $cert['status']);
        $this->assertStringContainsString('boom', $cert['message']);
    }

    public function testOverallStatus()
    {
        $c = fn($s, $critical = false) => HealthService::check('k', 'g', 'l', $s, '', [], $critical);
        $this->assertSame('ok', HealthService::overallStatus([$c('ok'), $c('skip')]));
        $this->assertSame('degraded', HealthService::overallStatus([$c('ok'), $c('warn')]));
        $this->assertSame('degraded', HealthService::overallStatus([$c('fail'), $c('warn', true)]));
        $this->assertSame('fail', HealthService::overallStatus([$c('ok'), $c('fail', true)]));
    }
}
