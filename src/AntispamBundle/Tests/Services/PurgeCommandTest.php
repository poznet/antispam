<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Command\PurgeCommand;
use AntispamBundle\Entity\DnsblCache;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\ConfigService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

class PurgeCommandTest extends TestCase
{
    private EntityManager $em;
    private ConfigService $config;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->config = new ConfigService($this->em);

        foreach (['-400 days', '-200 days', '-10 days', 'now'] as $age) {
            $this->em->persist((new SpamScoreLog())->setAccountEmail('jan@firma.pl')->setSender('s@x.pl')->setSubject($age)
                ->setScore(1)->setDecision('ham')->setScoredAt(new \DateTime($age)));
        }
        $provider = (new DnsblProvider())->setCacheTtl(7200);
        $this->setProviderFields($provider);
        $this->em->persist($provider);
        foreach (['-3 days' => '1.1.1.1', '-1 hour' => '2.2.2.2'] as $age => $ip) {
            $this->em->persist((new DnsblCache())->setIp($ip)->setZone('zen.example')->setCheckedAt(new \DateTime($age)));
        }
        $this->em->flush();
    }

    /** Fill the provider's other required columns whatever their setters are called. */
    private function setProviderFields(DnsblProvider $p): void
    {
        foreach (['setName' => 'Test', 'setZone' => 'zen.example', 'setHost' => 'zen.example'] as $setter => $v) {
            if (method_exists($p, $setter)) {
                $p->$setter($v);
            }
        }
    }

    private function purge(array $input = []): CommandTester
    {
        $tester = new CommandTester(new PurgeCommand($this->em, $this->config));
        $this->assertSame(0, $tester->execute($input));
        return $tester;
    }

    private function subjects(): array
    {
        $this->em->clear();
        $s = array_map(fn(SpamScoreLog $l) => $l->getSubject(), $this->em->getRepository(SpamScoreLog::class)->findAll());
        sort($s);
        return $s;
    }

    public function testDefaultRetentionIs180Days()
    {
        $this->purge();
        $this->assertSame(['-10 days', 'now'], $this->subjects());
        $this->assertSame(['2.2.2.2'], array_map(fn($c) => $c->getIp(), $this->em->getRepository(DnsblCache::class)->findAll()));
    }

    public function testRetentionFromConfigAndOption()
    {
        $this->config->set(PurgeCommand::CONFIG_RETENTION, '300');
        $this->purge();
        $this->assertSame(['-10 days', '-200 days', 'now'], $this->subjects());

        $this->purge(['--days' => '5']);
        $this->assertSame(['now'], $this->subjects());
    }

    public function testZeroKeepsEverythingAndDryRunDeletesNothing()
    {
        $tester = $this->purge(['--days' => '1', '--dry-run' => true]);
        $this->assertCount(4, $this->subjects());
        $this->assertStringContainsString('would delete 3', $tester->getDisplay());
        $this->assertCount(2, $this->em->getRepository(DnsblCache::class)->findAll());

        // Retention 0 keeps the score log; the DNSBL cache is still cleaned.
        $this->config->set(PurgeCommand::CONFIG_RETENTION, '0');
        $this->purge();
        $this->assertCount(4, $this->subjects());
        $this->assertCount(1, $this->em->getRepository(DnsblCache::class)->findAll());
    }

    public function testOldFinishedJobsArePurged()
    {
        $queue = new \AntispamBundle\Services\Jobs\JobQueue($this->em->getConnection(), $this->em);
        $old = $queue->enqueue(\AntispamBundle\Entity\BackgroundJob::TYPE_CERT_SYNC)->id;
        $active = $queue->enqueue(\AntispamBundle\Entity\BackgroundJob::TYPE_ACCOUNT_SCAN)->id;
        $this->em->getConnection()->executeStatement("UPDATE antispam_job SET created_at = ?", [(new \DateTime('-45 days'))->format('Y-m-d H:i:s')]);
        $this->em->getConnection()->update('antispam_job', ['status' => 'done'], ['id' => $old]);

        $this->assertStringContainsString('would delete 1 finished job', $this->purge(['--dry-run' => true])->getDisplay());
        $this->assertStringContainsString('deleted 1 finished job', $this->purge()->getDisplay());
        $this->assertSame([$active], array_map('intval', $this->em->getConnection()->fetchFirstColumn('SELECT id FROM antispam_job')), 'queued jobs survive');

        $this->config->set(\AntispamBundle\Entity\BackgroundJob::CONFIG_RETENTION, '0');
        $this->assertStringContainsString('keep forever', $this->purge()->getDisplay());
    }
}
