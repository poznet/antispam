<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Config;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ConfigService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;

/**
 * config.value used to be VARCHAR(255) holding serialize()d values, so a long
 * value (cert.last_error with a curl error, a key list) made MySQL strict mode
 * reject the write and crashed antispam:cert:sync inside its error handler.
 */
class ConfigServiceTest extends TestCase
{
    private EntityManager $em;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema([$this->em->getClassMetadata(Config::class)]);
    }

    public function testValueColumnIsText()
    {
        $mapping = $this->em->getClassMetadata(Config::class)->getFieldMapping('value');
        $this->assertSame('text', $mapping->type);
        $this->assertNull($mapping->length);
    }

    public function testLongValueRoundTrips()
    {
        $long = str_repeat('błąd pobierania: Could not resolve host ', 200); // ~8 KB
        $service = new ConfigService($this->em);
        $this->assertTrue($service->set('cert.last_error', $long));

        $this->em->clear();
        $this->assertSame($long, (new ConfigService($this->em))->get('cert.last_error'));
    }

    /** @param callable(string, mixed): void $onSet */
    private function certService(callable $onSet, array &$stored): CertHoleService
    {
        $config = $this->createMock(ConfigService::class);
        // Port 1 on localhost: the download fails at once, without network access.
        $config->method('get')->willReturnCallback(fn($k) => $k === 'cert.url' ? 'https://127.0.0.1:1/domains.txt' : null);
        $config->method('set')->willReturnCallback(function ($k, $v) use ($onSet, &$stored) {
            $onSet($k, $v);
            $stored[$k] = $v;
            return true;
        });
        return new CertHoleService($this->em, $config);
    }

    public function testCertSyncRecordsAClippedError()
    {
        $stored = [];
        $result = $this->certService(function () {}, $stored)->sync();

        $this->assertFalse($result['ok']);
        $this->assertNotSame('', $stored['cert.last_error']);
        $this->assertLessThanOrEqual(CertHoleService::MAX_ERROR_CHARS + 20, mb_strlen($stored['cert.last_error']));
    }

    public function testCertSyncSurvivesAFailingErrorWrite()
    {
        $stored = [];
        $service = $this->certService(function ($k) {
            if ($k === 'cert.last_error') {
                throw new \RuntimeException('Data too long for column value');
            }
        }, $stored);

        $result = $service->sync();
        $this->assertFalse($result['ok'], 'the download error is still reported');
        $this->assertStringContainsString('błąd pobierania', $result['message']);
    }

    public function testCertSyncCommandReportsInsteadOfCrashing()
    {
        $stored = [];
        $service = $this->certService(function () {
            throw new \RuntimeException('database is gone');
        }, $stored);
        $tester = new \Symfony\Component\Console\Tester\CommandTester(new \AntispamBundle\Command\CertSyncCommand($service));

        $this->assertSame(1, $tester->execute(['--force' => true]));
        $this->assertStringContainsString('database is gone', $tester->getDisplay());
    }
}
