<?php

namespace AntispamBundle\Tests\Services\Database;

use AntispamBundle\Services\Database\DatabaseUpgrader;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;
use Doctrine\Migrations\DependencyFactory;
use Doctrine\Migrations\Exception\AbortMigration;
use Doctrine\Migrations\Metadata\Storage\TableMetadataStorageConfiguration;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

/**
 * The migrations bundle is wired the way docs/migrations.md describes, and
 * every shipped migration (the baseline first) refuses to run outside
 * MySQL / MariaDB.
 */
class MigrationsConfigTest extends KernelTestCase
{
    private const BASELINE = 'DoctrineMigrations\Version20261028132604';

    private function migrations(): DependencyFactory
    {
        self::bootKernel();

        return self::getContainer()->get('doctrine.migrations.dependency_factory');
    }

    public function testConfiguration()
    {
        $config = $this->migrations()->getConfiguration();
        $projectDir = self::getContainer()->getParameter('kernel.project_dir');

        $this->assertSame(['DoctrineMigrations' => $projectDir . '/migrations'], $config->getMigrationDirectories());
        $storage = $config->getMetadataStorageConfiguration();
        $this->assertInstanceOf(TableMetadataStorageConfiguration::class, $storage);
        $this->assertSame('doctrine_migration_versions', $storage->getTableName());
        $this->assertFalse($config->isTransactional(), 'MySQL DDL commits implicitly');
        $this->assertFileExists((string)$config->getCustomTemplate());
        $this->assertStringContainsString('AbstractMySQLPlatform', file_get_contents((string)$config->getCustomTemplate()));
    }

    public function testBaselineIsTheFirstMigration()
    {
        $versions = array_map(fn($m) => (string)$m->getVersion(), $this->migrations()->getMigrationRepository()->getMigrations()->getItems());
        $this->assertNotEmpty($versions);
        $this->assertSame(self::BASELINE, $versions[0]);
        $this->assertTrue(class_exists(self::BASELINE));
    }

    public function testUpgraderIsWired()
    {
        self::bootKernel();
        $this->assertInstanceOf(DatabaseUpgrader::class, self::getContainer()->get(DatabaseUpgrader::class));
    }

    public function testEveryMigrationIsMysqlOnly()
    {
        $sqlite = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $files = glob(dirname(__DIR__, 5) . '/migrations/Version*.php');
        $this->assertNotEmpty($files);
        foreach ($files as $file) {
            require_once $file;
            $class = 'DoctrineMigrations\\' . basename($file, '.php');
            /** @var AbstractMigration $migration */
            $migration = new $class($sqlite, new NullLogger());
            foreach (['up', 'down'] as $direction) {
                try {
                    $migration->$direction(new Schema());
                    $this->fail(sprintf('%s::%s() must abortIf() the platform is not MySQL / MariaDB', $class, $direction));
                } catch (AbortMigration $e) {
                    $this->assertStringContainsString('MySQL', $e->getMessage());
                }
            }
        }
    }
}
