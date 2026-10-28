<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Config;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\HealthAlerter;
use AntispamBundle\Services\HealthService;
use AntispamBundle\Services\HealthSettings;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\RawMessage;

/** Alert state machine: threshold, no repeats, recovery, retries, payload. */
class HealthAlerterTest extends TestCase
{
    private ConfigService $config;
    private HealthSettings $settings;
    /** @var Email[] */
    public array $mails = [];
    /** @var array<int, array{0:string, 1:array}> */
    public array $hooks = [];
    public ?string $hookError = null;
    public ?\Throwable $mailError = null;

    protected function setUp(): void
    {
        $orm = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $orm);
        (new SchemaTool($em))->createSchema([$em->getClassMetadata(Config::class)]);
        $this->config = new ConfigService($em);
        $this->settings = new HealthSettings($this->config, null);
        $this->config->set('health.alert_email', 'ops@example.com');
        $this->config->set('digest.from_email', 'antispam@example.com');
        $this->config->set('digest.base_url', 'https://antispam.example.com');
    }

    private function alerter(): HealthAlerter
    {
        $test = $this;
        $mailer = new class($test) implements MailerInterface {
            public function __construct(private HealthAlerterTest $test) {}
            public function send(RawMessage $message, ?Envelope $envelope = null): void
            {
                if ($this->test->mailError) {
                    throw $this->test->mailError;
                }
                $this->test->mails[] = $message;
            }
        };
        return new class($this->config, $this->settings, $mailer, $test) extends HealthAlerter {
            public function __construct($config, $settings, $mailer, private HealthAlerterTest $test)
            {
                parent::__construct($config, $settings, $mailer);
            }
            protected function postJson(string $url, array $payload): ?string
            {
                $this->test->hooks[] = [$url, $payload];
                return $this->test->hookError;
            }
        };
    }

    private static function report(array $statuses, string $overall = 'degraded'): array
    {
        $checks = [];
        foreach ($statuses as $key => $status) {
            $checks[] = HealthService::check($key, 'g', 'Check ' . $key, $status, 'msg ' . $key);
        }
        return ['status' => $overall, 'checked_at' => '2026-10-28T12:00:00+00:00', 'full' => false, 'checks' => $checks];
    }

    public function testAlertAfterThresholdOnceThenRecovery()
    {
        $alerter = $this->alerter(); // default threshold 2

        $r = $alerter->process(self::report(['db' => 'ok', 'clamav' => 'fail']));
        $this->assertSame([], $r['problems'], 'first failure is below the threshold');
        $this->assertCount(0, $this->mails);

        $r = $alerter->process(self::report(['db' => 'ok', 'clamav' => 'fail']));
        $this->assertSame(['clamav'], array_column($r['problems'], 'key'));
        $this->assertSame(['email'], $r['sent']);
        $this->assertCount(1, $this->mails);
        $this->assertSame('[Antispam] Problem: Check clamav', $this->mails[0]->getSubject());
        $this->assertSame('ops@example.com', $this->mails[0]->getTo()[0]->getAddress());
        $this->assertSame('antispam@example.com', $this->mails[0]->getFrom()[0]->getAddress());
        $this->assertStringContainsString('https://antispam.example.com/system/status', $this->mails[0]->getTextBody());

        // still failing: no repeat
        for ($i = 0; $i < 3; $i++) {
            $r = $alerter->process(self::report(['db' => 'ok', 'clamav' => 'fail']));
            $this->assertSame([], $r['problems']);
        }
        $this->assertCount(1, $this->mails);
        $this->assertSame(5, $alerter->getState()['checks']['clamav']['fails']);

        // recovered: one message, state cleared
        $r = $alerter->process(self::report(['db' => 'ok', 'clamav' => 'ok'], 'ok'));
        $this->assertSame(['clamav'], array_column($r['recovered'], 'key'));
        $this->assertCount(2, $this->mails);
        $this->assertSame('[Antispam] Przywrócono: Check clamav', $this->mails[1]->getSubject());
        $this->assertArrayNotHasKey('clamav', $alerter->getState()['checks']);

        $alerter->process(self::report(['db' => 'ok', 'clamav' => 'ok'], 'ok'));
        $this->assertCount(2, $this->mails, 'no second recovery');
    }

    public function testFlappingBelowThresholdNeverAlerts()
    {
        $alerter = $this->alerter();
        foreach (['fail', 'ok', 'fail', 'ok', 'fail'] as $status) {
            $alerter->process(self::report(['db' => 'ok', 'x' => $status]));
        }
        $this->assertCount(0, $this->mails);
    }

    public function testWarningsAlertOnlyWhenEnabled()
    {
        $this->config->set('health.fail_threshold', 1);
        $alerter = $this->alerter();
        $alerter->process(self::report(['db' => 'ok', 'x' => 'warn']));
        $this->assertCount(0, $this->mails);

        $this->config->set('health.alert_on_warn', '1');
        $r = $alerter->process(self::report(['db' => 'ok', 'x' => 'warn']));
        $this->assertSame(['x'], array_column($r['problems'], 'key'));
    }

    public function testAggregatesProblemsInOneNotification()
    {
        $this->config->set('health.fail_threshold', 1);
        $r = $this->alerter()->process(self::report(['db' => 'ok', 'a' => 'fail', 'b' => 'fail']));
        $this->assertCount(2, $r['problems']);
        $this->assertCount(1, $this->mails);
        $this->assertSame('[Antispam] 2 kontrole nie przechodzą', $this->mails[0]->getSubject());
    }

    public function testWebhookPayload()
    {
        $this->config->set('health.fail_threshold', 1);
        $this->config->set('health.alert_email', '');
        $this->config->set('digest.from_email', '');
        $this->config->set('health.webhook_url', 'https://hooks.example.com/T/B/x');
        $alerter = $this->alerter();

        $r = $alerter->process(self::report(['db' => 'ok', 'scheduler' => 'fail'], 'fail'));
        $this->assertSame(['webhook'], $r['sent']);
        $this->assertCount(0, $this->mails);
        [$url, $payload] = $this->hooks[0];
        $this->assertSame('https://hooks.example.com/T/B/x', $url);
        $this->assertSame('problem', $payload['type']);
        $this->assertSame('fail', $payload['status']);
        $this->assertSame('https://antispam.example.com', $payload['instance']);
        $this->assertSame([['key' => 'scheduler', 'label' => 'Check scheduler', 'status' => 'fail', 'message' => 'msg scheduler', 'since' => '2026-10-28T12:00:00+00:00']], $payload['problems']);
        $this->assertStringContainsString('Check scheduler', $payload['text']);
        $this->assertNotFalse(json_encode($payload));

        $alerter->process(self::report(['db' => 'ok', 'scheduler' => 'ok'], 'ok'));
        $this->assertSame('recovery', $this->hooks[1][1]['type']);
        $this->assertSame('scheduler', $this->hooks[1][1]['recovered'][0]['key']);
    }

    public function testAllChannelsFailingRetriesNextRun()
    {
        $this->config->set('health.fail_threshold', 1);
        $this->mailError = new \RuntimeException('SMTP down');
        $alerter = $this->alerter();

        $r = $alerter->process(self::report(['db' => 'ok', 'x' => 'fail']));
        $this->assertSame([], $r['sent']);
        $this->assertStringContainsString('SMTP down', $r['errors'][0]);
        $this->assertFalse($alerter->getState()['checks']['x']['alerted']);
        $this->assertSame($r['errors'], $alerter->getState()['last_errors']);

        $this->mailError = null;
        $r = $alerter->process(self::report(['db' => 'ok', 'x' => 'fail']));
        $this->assertSame(['email'], $r['sent']);
        $this->assertTrue($alerter->getState()['checks']['x']['alerted']);
    }

    public function testOneChannelSucceedingCountsAsSent()
    {
        $this->config->set('health.fail_threshold', 1);
        $this->config->set('health.webhook_url', 'https://hooks.example.com/x');
        $this->hookError = 'HTTP 500';
        $alerter = $this->alerter();
        $r = $alerter->process(self::report(['db' => 'ok', 'x' => 'fail']));
        $this->assertSame(['email'], $r['sent']);
        $this->assertSame(['Webhook: HTTP 500'], $r['errors']);
        $this->assertTrue($alerter->getState()['checks']['x']['alerted']);
    }

    public function testDisabledAlertsSendNothingButCount()
    {
        $this->config->set('health.alert_enabled', '0');
        $alerter = $this->alerter();
        $alerter->process(self::report(['db' => 'ok', 'x' => 'fail']));
        $alerter->process(self::report(['db' => 'ok', 'x' => 'fail']));
        $this->assertCount(0, $this->mails);
        $this->assertSame(2, $alerter->getState()['checks']['x']['fails']);

        // enabled later while still failing: alerts on the next run
        $this->config->set('health.alert_enabled', '1');
        $r = $alerter->process(self::report(['db' => 'ok', 'x' => 'fail']));
        $this->assertSame(['x'], array_column($r['problems'], 'key'));
    }

    public function testMissingChecksKeptWhileDatabaseDownDroppedOtherwise()
    {
        $this->config->set('health.fail_threshold', 1);
        $alerter = $this->alerter();
        $alerter->process(self::report(['db' => 'ok', 'account:7' => 'fail']));
        $this->assertCount(1, $this->mails);

        // DB down: account checks were not run - no false recovery
        $alerter->process(self::report(['db' => 'fail'], 'fail'));
        $state = $alerter->getState();
        $this->assertTrue($state['checks']['account:7']['alerted']);
        $this->assertCount(2, $this->mails, 'only the db problem');

        // DB back, account deleted: dropped silently
        $alerter->process(self::report(['db' => 'ok'], 'ok'));
        $this->assertArrayNotHasKey('account:7', $alerter->getState()['checks']);
        $this->assertSame('[Antispam] Przywrócono: Check db', end($this->mails)->getSubject());
    }

    public function testNoChannelMarksAsHandled()
    {
        $this->config->set('health.fail_threshold', 1);
        $this->config->set('health.alert_email', '');
        $this->config->set('digest.from_email', '');
        $alerter = $this->alerter();
        $this->assertFalse($alerter->hasChannels());
        $r = $alerter->process(self::report(['db' => 'ok', 'x' => 'fail']));
        $this->assertSame([], $r['sent']);
        $this->assertStringContainsString('Brak odbiorcy', $r['errors'][0]);
        $this->assertTrue($alerter->getState()['checks']['x']['alerted']);
    }

    public function testSendTest()
    {
        [$sent, $errors] = $this->alerter()->sendTest();
        $this->assertSame(['email'], $sent);
        $this->assertSame([], $errors);
        $this->assertSame('[Antispam] Test alertów', $this->mails[0]->getSubject());
    }
}
