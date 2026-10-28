<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\CronRun;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\HealthDataSource;
use AntispamBundle\Services\HealthMetrics;
use AntispamBundle\Services\HealthService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;

/** The DQL behind the checks and /metrics, on SQLite. */
class HealthDataSourceTest extends TestCase
{
    private EntityManager $em;
    private HealthDataSource $data;

    protected function setUp(): void
    {
        $orm = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $orm);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->data = new HealthDataSource($this->em, sys_get_temp_dir());
    }

    private function cron(string $cmd, string $startedAt, ?int $exit): CronRun
    {
        $run = new CronRun($cmd);
        (new \ReflectionProperty(CronRun::class, 'startedAt'))->setValue($run, new \DateTime($startedAt));
        if ($exit !== null) {
            $run->finish($exit, '');
        }
        $this->em->persist($run);
        return $run;
    }

    private function log(string $email, string $decision, ?string $outcome, string $at, bool $initial = false): void
    {
        $log = (new SpamScoreLog())->setAccountEmail($email)->setDecision($decision)->setOutcome($outcome)->setInitialScan($initial);
        (new \ReflectionProperty(SpamScoreLog::class, 'scoredAt'))->setValue($log, new \DateTime($at));
        $this->em->persist($log);
    }

    public function testCronQueries()
    {
        $this->cron('antispam:agent:scan-all', '-30 minutes', 0);
        $newest = $this->cron('antispam:agent:scan-all', '-5 minutes', 1);
        $this->cron('antispam:purge', '-3 days', 0);
        $this->cron('antispam:feed:sync', '-1 hour', null);
        $this->em->flush();

        $last = $this->data->lastCronRuns();
        $keys = array_keys($last);
        sort($keys);
        $this->assertSame(['antispam:agent:scan-all', 'antispam:feed:sync', 'antispam:purge'], $keys);
        $this->assertSame($newest, $last['antispam:agent:scan-all']);

        $recent = $this->data->recentCronRuns('antispam:agent:scan-all');
        $this->assertSame($newest, $recent[0]);
        $this->assertCount(2, $recent);

        $this->assertSame(0, $this->data->lastSuccessfulCronRun('antispam:agent:scan-all')->getExitCode());
        $this->assertNull($this->data->lastSuccessfulCronRun('antispam:feed:sync'));

        $stats = $this->data->cronStatsSince(new \DateTimeImmutable('-24 hours'));
        $this->assertSame(['runs' => 2, 'failures' => 1], $stats['antispam:agent:scan-all']);
        $this->assertSame(['runs' => 1, 'failures' => 0], $stats['antispam:feed:sync'], 'a running job is not a failure');
        $this->assertArrayNotHasKey('antispam:purge', $stats);
    }

    public function testScoreLogQueries()
    {
        $this->log('a@example.com', SpamScoreLog::DECISION_QUARANTINE, SpamScoreLog::OUTCOME_QUARANTINED, '-1 hour');
        $this->log('a@example.com', SpamScoreLog::DECISION_QUARANTINE, SpamScoreLog::OUTCOME_QUARANTINED, '-2 hours');
        $this->log('b@example.com', SpamScoreLog::DECISION_QUARANTINE, SpamScoreLog::OUTCOME_QUARANTINED, '-3 days');
        $this->log('b@example.com', SpamScoreLog::DECISION_QUARANTINE, SpamScoreLog::OUTCOME_QUARANTINED, '-1 hour', true);
        $this->log('b@example.com', SpamScoreLog::DECISION_SPAM, SpamScoreLog::OUTCOME_SPAM_FOLDER, '-1 hour');
        $this->em->flush();

        $since = new \DateTimeImmutable('-24 hours');
        $this->assertSame(['a@example.com' => 2], $this->data->quarantinedSince($since));
        $this->assertSame(['ham' => 0, 'quarantine' => 2, 'spam' => 1, 'whitelisted' => 0], $this->data->decisionsSince($since));
    }

    public function testFilesystemFactsAndSchema()
    {
        $this->data->pingDatabase();
        $this->assertNull($this->data->databaseSize(), 'size is only read on MySQL/MariaDB');
        $disk = $this->data->diskSpace();
        $this->assertGreaterThan(0, $disk['free']);
        // SQLite reports table rebuilds for some columns; what matters is that
        // DROPs (legacy columns the boot-time update keeps) are never counted.
        foreach ($this->data->pendingSchemaChanges() as $sql) {
            $this->assertDoesNotMatchRegularExpression('/^\s*(DROP |ALTER TABLE \S+ DROP)/i', $sql);
        }
    }

    public function testMetricsOutput()
    {
        $this->cron('antispam:agent:scan-all', '-5 minutes', 0);
        $this->cron('antispam:agent:scan-all', '-10 minutes', 2);
        $this->log('a@example.com', SpamScoreLog::DECISION_QUARANTINE, SpamScoreLog::OUTCOME_QUARANTINED, '-1 hour');
        $this->em->flush();

        $report = [
            'status' => 'degraded',
            'checked_at' => date(DATE_ATOM),
            'full' => false,
            'checks' => [
                HealthService::check('db', 'system', 'Baza danych', 'ok', '', ['size_bytes' => 1000], true),
                HealthService::check('cron:antispam:agent:scan-all', 'cron', 'Skan', 'ok', '', ['age_seconds' => 300]),
                HealthService::check('account:1', 'accounts', 'a"b@example.com', 'fail', '', ['type' => 'imap', 'last_scan_age_seconds' => 7200]),
                HealthService::check('clamav', 'services', 'ClamAV', 'skip', ''),
                HealthService::check('disk', 'system', 'Dysk', 'warn', '', ['free_bytes' => 42]),
            ],
        ];
        $text = (new HealthMetrics($this->data))->render($report);

        $this->assertStringContainsString("# TYPE antispam_health_status gauge\nantispam_health_status 1\n", $text);
        $this->assertStringContainsString('antispam_health_check_status{check="account:1",group="accounts"} 2', $text);
        $this->assertStringNotContainsString('check="clamav"', $text, 'skipped checks are omitted');
        $this->assertStringContainsString('antispam_account_last_scan_age_seconds{account="a\\"b@example.com",type="imap"} 7200', $text);
        $this->assertStringContainsString('antispam_cron_last_run_age_seconds{command="antispam:agent:scan-all"} 300', $text);
        $this->assertStringContainsString('antispam_scans_24h 2', $text);
        $this->assertStringContainsString('antispam_cron_failures_24h{command="antispam:agent:scan-all"} 1', $text);
        $this->assertStringContainsString('antispam_decisions_24h{decision="quarantine"} 1', $text);
        $this->assertStringContainsString('antispam_quarantined_24h{account="a@example.com"} 1', $text);
        $this->assertStringContainsString('antispam_database_size_bytes 1000', $text);
        $this->assertStringContainsString('antispam_disk_free_bytes 42', $text);
        foreach (explode("\n", trim($text)) as $line) {
            $this->assertMatchesRegularExpression('/^(# (HELP|TYPE) [a-z_0-9]+ .+|[a-z_0-9]+(\{[^}]*\})? -?\d+(\.\d+)?)$/', $line);
        }
    }

    public function testMetricsSurviveDatabaseErrors()
    {
        $data = $this->createMock(HealthDataSource::class);
        $data->method('cronStatsSince')->willThrowException(new \RuntimeException('gone'));
        $text = (new HealthMetrics($data))->render(['status' => 'fail', 'checks' => [HealthService::check('db', 'system', 'DB', 'fail', 'x', [], true)]]);
        $this->assertStringContainsString('antispam_health_status 2', $text);
        $this->assertStringContainsString('antispam_metrics_activity_error 1', $text);
    }
}
