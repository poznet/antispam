<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Config;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\HealthSettings;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;

class HealthSettingsTest extends TestCase
{
    private ConfigService $config;

    protected function setUp(): void
    {
        $orm = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $orm);
        (new SchemaTool($em))->createSchema([$em->getClassMetadata(Config::class)]);
        $this->config = new ConfigService($em);
    }

    public function testDefaults()
    {
        $s = new HealthSettings($this->config);
        $this->assertTrue($s->isAlertEnabled());
        $this->assertFalse($s->isAlertOnWarn());
        $this->assertSame(2, $s->getFailThreshold());
        $this->assertSame(60, $s->getScanMaxAge());
        $this->assertSame('', $s->getToken());
        $this->assertFalse($s->isValidToken(''), 'no token configured = details disabled');
        $this->assertSame([], $s->getEffectiveAlertEmails());
    }

    public function testRecipientsFallBackToDigestAddress()
    {
        $this->config->set('digest.from_email', 'antispam@example.com');
        $s = new HealthSettings($this->config);
        $this->assertSame(['antispam@example.com'], $s->getEffectiveAlertEmails());
        $this->assertSame('antispam@example.com', $s->getFromEmail());

        $this->config->set('health.alert_email', 'a@example.com, b@example.com');
        $this->assertSame(['a@example.com', 'b@example.com'], $s->getEffectiveAlertEmails());
    }

    public function testSaveValidates()
    {
        $s = new HealthSettings($this->config);
        $errors = $s->save(['alert_email' => 'ok@example.com, not-an-email', 'webhook_url' => 'ftp://x', 'token' => 'short']);
        $this->assertCount(3, $errors);
        $this->assertNull($this->config->get('health.alert_email'), 'nothing saved on error');

        $this->assertSame([], $s->save([
            'alert_enabled' => '1', 'alert_email' => 'ops@example.com;dev@example.com', 'webhook_url' => 'https://hooks.slack.com/services/T/B/X',
            'fail_threshold' => '3', 'alert_on_warn' => '1', 'scan_max_age' => '1', 'token' => 'abcdefghijklmnop0123',
        ]));
        $this->assertSame(['ops@example.com', 'dev@example.com'], $s->getAlertEmails());
        $this->assertSame('https://hooks.slack.com/services/T/B/X', $s->getWebhookUrl());
        $this->assertSame(3, $s->getFailThreshold());
        $this->assertTrue($s->isAlertOnWarn());
        $this->assertSame(60, $s->getScanMaxAge(), 'too small falls back to the default');
        $this->assertTrue($s->isValidToken('abcdefghijklmnop0123'));
        $this->assertFalse($s->isValidToken('abcdefghijklmnop012'));

        $s->save([]);
        $this->assertFalse($s->isAlertEnabled());
        $this->assertSame('', $s->getToken());
    }

    public function testEnvTokenWins()
    {
        $this->config->set('health.token', 'stored-token-stored-token');
        $s = new HealthSettings($this->config, 'env-token-env-token-1');
        $this->assertTrue($s->isTokenFromEnv());
        $this->assertTrue($s->isValidToken('env-token-env-token-1'));
        $this->assertFalse($s->isValidToken('stored-token-stored-token'));

        $s->save(['token' => '']);
        $this->assertSame('stored-token-stored-token', $this->config->get('health.token'), 'the form does not touch the stored token while HEALTH_TOKEN is set');
    }
}
