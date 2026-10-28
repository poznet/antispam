<?php

namespace AntispamBundle\Tests\Command;

use AntispamBundle\Command\HealthCheckCommand;
use AntispamBundle\Services\HealthAlerter;
use AntispamBundle\Services\HealthService;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

/** antispam:health:check runs without the scheduler: checks, alerts, exit codes. */
class HealthCheckCommandTest extends TestCase
{
    private function tester(string $status, ?HealthAlerter $alerter = null, ?bool $expectFull = null): CommandTester
    {
        $health = $this->createMock(HealthService::class);
        $health->method('run')->willReturnCallback(function (bool $full) use ($status, $expectFull) {
            if ($expectFull !== null) {
                $this->assertSame($expectFull, $full);
            }
            return ['status' => $status, 'checked_at' => '2026-10-28T12:00:00+00:00', 'full' => $full, 'checks' => [
                HealthService::check('clamav', 'services', 'ClamAV', $status === 'ok' ? 'ok' : 'fail', 'Nie odpowiada'),
            ]];
        });
        return new CommandTester(new HealthCheckCommand($health, $alerter ?? $this->createMock(HealthAlerter::class)));
    }

    public function testRunsChecksAndProcessesAlerts()
    {
        $alerter = $this->createMock(HealthAlerter::class);
        $alerter->expects($this->once())->method('process')->willReturn([
            'problems' => [['label' => 'ClamAV']], 'recovered' => [], 'sent' => ['email'], 'errors' => [],
        ]);
        $tester = $this->tester('degraded', $alerter, false);
        $this->assertSame(0, $tester->execute([]), 'a failing check does not fail the cron job itself');
        $out = $tester->getDisplay();
        $this->assertStringContainsString('FAIL ClamAV: Nie odpowiada', $out);
        $this->assertStringContainsString('Alert: ClamAV', $out);
        $this->assertStringContainsString('Notification sent via email', $out);
    }

    public function testNoAlertFullJsonAndExitCode()
    {
        $alerter = $this->createMock(HealthAlerter::class);
        $alerter->expects($this->never())->method('process');
        $tester = $this->tester('fail', $alerter, true);
        $this->assertSame(2, $tester->execute(['--no-alert' => true, '--full' => true, '--json' => true, '--exit-code' => true]));
        $this->assertSame('fail', json_decode($tester->getDisplay(), true)['status']);

        $this->assertSame(1, $this->tester('degraded')->execute(['--no-alert' => true, '--exit-code' => true]));
        $this->assertSame(0, $this->tester('ok')->execute(['--no-alert' => true, '--exit-code' => true]));
    }
}
