<?php

namespace AntispamBundle\Tests\Services\Database;

use AntispamBundle\Command\DbUpgradeCommand;
use AntispamBundle\Services\Database\DatabaseState;
use AntispamBundle\Services\Database\DatabaseUpgrader;
use Doctrine\DBAL\DriverManager;
use Doctrine\Migrations\Configuration\Configuration;
use Doctrine\Migrations\Configuration\EntityManager\ExistingEntityManager;
use Doctrine\Migrations\Configuration\Migration\ExistingConfiguration;
use Doctrine\Migrations\DependencyFactory;
use Doctrine\Migrations\Metadata\Storage\TableMetadataStorageConfiguration;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * antispam:db:upgrade decision logic and the three paths against an in-memory
 * SQLite database, with a platform-neutral fixture migration standing in for
 * the MySQL-only baseline (the real paths on MariaDB: docs/migrations.md).
 */
class DatabaseUpgraderTest extends TestCase
{
    private const FIXTURE = 'AntispamBundle\Tests\Fixtures\Migrations\Version20000101000000';

    private EntityManager $em;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 3) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
    }

    private function upgrader(): DatabaseUpgrader
    {
        $config = new Configuration();
        $config->addMigrationsDirectory('AntispamBundle\Tests\Fixtures\Migrations', dirname(__DIR__, 2) . '/Fixtures/Migrations');
        $storage = new TableMetadataStorageConfiguration();
        $storage->setTableName('doctrine_migration_versions');
        $config->setMetadataStorageConfiguration($storage);
        $config->setTransactional(false);

        $migrations = DependencyFactory::fromEntityManager(new ExistingConfiguration($config), new ExistingEntityManager($this->em));

        return new class($this->em, $migrations) extends DatabaseUpgrader {
            // SQLite always "rebuilds" the string-keyed antispam_cert_domain
            // (a DBAL SQLite comparator artefact, not drift on MySQL).
            public function pendingSchemaChanges(): array
            {
                return array_values(array_filter(parent::pendingSchemaChanges(), fn($s) => !str_contains($s, 'antispam_cert_domain')));
            }
        };
    }

    private function runCommand(): CommandTester
    {
        $tester = new CommandTester(new DbUpgradeCommand($this->upgrader()));
        $tester->execute([]);

        return $tester;
    }

    private function createCurrentSchema(): void
    {
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
    }

    private function tables(): array
    {
        return $this->em->getConnection()->createSchemaManager()->listTableNames();
    }

    public static function decisions(): array
    {
        $entity = ['antispam_account', 'config'];

        return [
            'empty database' => [[], 0, DatabaseState::FRESH],
            'only foreign tables' => [['wp_posts'], 0, DatabaseState::FRESH],
            'migrations table, nothing recorded, no antispam table' => [['doctrine_migration_versions'], 0, DatabaseState::FRESH],
            'schema:update install' => [['antispam_account', 'config'], 0, DatabaseState::LEGACY],
            'partial old install' => [['CONFIG'], 0, DatabaseState::LEGACY],
            'adoption died after creating the migrations table' => [['config', 'doctrine_migration_versions'], 0, DatabaseState::LEGACY],
            'migrated' => [['config', 'doctrine_migration_versions'], 1, DatabaseState::MIGRATED],
            'migrated, tables gone (still trust the history)' => [['doctrine_migration_versions'], 3, DatabaseState::MIGRATED],
        ];
    }

    #[DataProvider('decisions')]
    public function testDecide(array $existing, int $executed, string $expected)
    {
        $this->assertSame($expected, DatabaseUpgrader::decide($existing, ['antispam_account', 'config'], $executed));
    }

    public function testFreshDatabaseRunsAllMigrations()
    {
        $state = $this->upgrader()->inspect();
        $this->assertSame(DatabaseState::FRESH, $state->state);
        $this->assertSame([self::FIXTURE], $state->pending);

        $tester = $this->runCommand();
        $this->assertStringContainsString('Database state: fresh', $tester->getDisplay());
        $this->assertContains('fixture_marker', $this->tables());
        $this->assertSame(DatabaseState::MIGRATED, $this->upgrader()->inspect()->state);
        $this->assertSame([], $this->upgrader()->pendingMigrations());
    }

    public function testLegacyInstallIsUpdatedAndMarkedWithoutRunningMigrations()
    {
        $this->createCurrentSchema();
        $connection = $this->em->getConnection();
        $connection->executeStatement('DROP TABLE antispam_audit_log');                // older release
        $connection->executeStatement('CREATE TABLE foreign_stats (id INTEGER NOT NULL)'); // not ours
        $connection->insert('config', ['name' => 'scoring.threshold', 'value' => '7']);

        $this->assertSame(DatabaseState::LEGACY, $this->upgrader()->inspect()->state);
        $this->assertSame(['foreign_stats'], $this->upgrader()->inspect()->foreignTables);

        $tester = $this->runCommand();
        $display = $tester->getDisplay();
        $this->assertSame(Command::SUCCESS, $tester->getStatusCode(), $display);
        $this->assertStringContainsString('adopting it', $display);
        $this->assertStringContainsString('[skipped, table kept] DROP TABLE foreign_stats', $display);

        $tables = $this->tables();
        $this->assertContains('antispam_audit_log', $tables, 'schema:update step added the missing table');
        $this->assertContains('foreign_stats', $tables, 'DROP TABLE is never run');
        $this->assertNotContains('fixture_marker', $tables, 'migrations are marked, not executed');
        $this->assertSame('7', $connection->fetchOne("SELECT value FROM config WHERE name = 'scoring.threshold'"), 'data survives');

        $state = $this->upgrader()->inspect();
        $this->assertSame(DatabaseState::MIGRATED, $state->state);
        $this->assertSame([self::FIXTURE], $state->executed);
        $this->assertSame([], $state->pending);
    }

    public function testMigratedDatabaseIsANoOp()
    {
        $this->createCurrentSchema();
        $this->runCommand();
        $tester = $this->runCommand();
        $this->assertSame(Command::SUCCESS, $tester->getStatusCode());
        $this->assertStringContainsString('Database state: migrated', $tester->getDisplay());
        $this->assertStringContainsString('No pending migrations.', $tester->getDisplay());
    }

    public function testDryRunChangesNothing()
    {
        $this->createCurrentSchema();
        $before = $this->tables();

        $tester = new CommandTester(new DbUpgradeCommand($this->upgrader()));
        $tester->execute(['--dry-run' => true]);

        $this->assertSame(Command::SUCCESS, $tester->getStatusCode());
        $this->assertStringContainsString('(dry run) Database state: legacy', $tester->getDisplay());
        $this->assertEqualsCanonicalizing($before, $this->tables(), 'no migrations table, nothing created');
        $this->assertSame(DatabaseState::LEGACY, $this->upgrader()->inspect()->state);
    }

    public function testEntityChangeWithoutMigrationExitsWithWarnings()
    {
        // Migrated (the fixture is recorded) but the entity tables were never created:
        // the drift check must flag it and the exit code must be 2.
        $tester = $this->runCommand();
        $this->assertSame(DbUpgradeCommand::EXIT_WARNINGS, $tester->getStatusCode());
        $this->assertStringContainsString('entities still differ from the database', $tester->getDisplay());
    }

    public function testFailureIsReportedWithExitCode1()
    {
        $this->em->getConnection()->executeStatement('CREATE TABLE fixture_marker (id INTEGER NOT NULL)');

        $tester = $this->runCommand();
        $this->assertSame(Command::FAILURE, $tester->getStatusCode());
        $this->assertStringContainsString('[db:upgrade] FAILED', $tester->getDisplay());
    }
}
