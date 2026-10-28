<?php

namespace AntispamBundle\Services\Database;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\Migrations\DependencyFactory;
use Doctrine\Migrations\Metadata\AvailableMigration;
use Doctrine\Migrations\Metadata\ExecutedMigration;
use Doctrine\Migrations\Metadata\Storage\TableMetadataStorageConfiguration;
use Doctrine\Migrations\MigratorConfiguration;
use Doctrine\Migrations\Version\Direction;
use Doctrine\Migrations\Version\ExecutionResult;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Brings the database to the schema of this release (antispam:db:upgrade,
 * docs/migrations.md):
 *
 *  - FRESH    (no antispam table)            -> run all migrations
 *  - LEGACY   (antispam tables, no migration -> doctrine:schema:update once (as the
 *              recorded; made by schema:update)  old boot did), mark every migration
 *                                                executed, then migrate (no-op)
 *  - MIGRATED (a migration is recorded)      -> run the pending migrations
 *
 * The decision depends on "is any migration recorded", not on "does the
 * migrations table exist": a LEGACY adoption that died after creating the
 * table but before marking the versions is simply adopted again.
 */
class DatabaseUpgrader
{
    private const LOCK_NAME = 'antispam_db_upgrade';

    public function __construct(
        private EntityManagerInterface $em,
        #[Autowire(service: 'doctrine.migrations.dependency_factory')] private DependencyFactory $migrations,
    ) {
    }

    /**
     * The decision itself, without database access.
     *
     * @param string[] $existingTables tables in the database
     * @param string[] $entityTables   tables of the entity mapping
     * @param int      $executedCount  migrations recorded as executed
     */
    public static function decide(array $existingTables, array $entityTables, int $executedCount): string
    {
        if ($executedCount > 0) {
            return DatabaseState::MIGRATED;
        }

        return self::intersect($existingTables, $entityTables) === [] ? DatabaseState::FRESH : DatabaseState::LEGACY;
    }

    /**
     * Route the migrations' log (executed SQL, warnings) to the console. Only
     * possible before the migrations services are first used.
     */
    public function setLogger(LoggerInterface $logger): void
    {
        if (!$this->migrations->isFrozen()) {
            $this->migrations->setService(LoggerInterface::class, $logger);
        }
    }

    public function inspect(): DatabaseState
    {
        $existing = $this->em->getConnection()->createSchemaManager()->listTableNames();
        $entity = $this->entityTables();
        $migrationsTable = $this->migrationsTableName();

        $executed = array_map(fn(ExecutedMigration $m) => (string)$m->getVersion(),
            $this->migrations->getMetadataStorage()->getExecutedMigrations()->getItems());
        $calculator = $this->migrations->getMigrationStatusCalculator();
        $pending = array_map(fn(AvailableMigration $m) => (string)$m->getVersion(), $calculator->getNewMigrations()->getItems());
        $unknown = array_map(fn(ExecutedMigration $m) => (string)$m->getVersion(), $calculator->getExecutedUnavailableMigrations()->getItems());

        $foreign = array_values(array_filter($existing, fn(string $t) => strcasecmp($t, $migrationsTable) !== 0
            && self::intersect([$t], $entity) === []));

        return new DatabaseState(
            self::decide($existing, $entity, count($executed)),
            self::intersect($existing, $entity),
            $foreign,
            self::intersect($existing, [$migrationsTable]) !== [],
            $executed,
            $pending,
            $unknown,
        );
    }

    /** @return string[] versions not executed yet, in execution order */
    public function pendingMigrations(): array
    {
        return array_map(fn(AvailableMigration $m) => (string)$m->getVersion(),
            $this->migrations->getMigrationStatusCalculator()->getNewMigrations()->getItems());
    }

    /**
     * Run the pending migrations.
     *
     * @return string[] executed versions
     */
    public function migrate(): array
    {
        $pending = $this->pendingMigrations();
        if ($pending === []) {
            return [];
        }
        $this->migrations->getMetadataStorage()->ensureInitialized();
        $plan = $this->migrations->getMigrationPlanCalculator()->getPlanForVersions(
            array_map(fn(AvailableMigration $m) => $m->getVersion(), $this->migrations->getMigrationStatusCalculator()->getNewMigrations()->getItems()),
            Direction::UP,
        );
        $this->migrations->getMigrator()->migrate($plan, (new MigratorConfiguration())->setAllOrNothing(false));

        return $pending;
    }

    /**
     * LEGACY step 1: what doctrine:schema:update --force would run, minus
     * DROP TABLE (a table the mapping does not know - another app's, or one
     * from a newer release - is left alone) and minus anything touching the
     * migrations table.
     *
     * @return array{run: string[], skipped: string[]}
     */
    public function schemaUpdatePlan(): array
    {
        $entity = $this->entityTables();
        $foreign = array_filter($this->em->getConnection()->createSchemaManager()->listTableNames(),
            fn(string $t) => self::intersect([$t], $entity) === []);
        $run = $skipped = [];
        foreach ($this->schemaUpdateSql() as $sql) {
            // only tables that exist now and are not ours; a DROP TABLE of an
            // entity / temporary table is part of a table rebuild (SQLite)
            if (preg_match('/^\s*DROP TABLE\s+[`"]?([^\s`"]+)/i', $sql, $m) && self::intersect([$m[1]], $foreign) !== []) {
                $skipped[] = $sql;
            } else {
                $run[] = $sql;
            }
        }

        return ['run' => $run, 'skipped' => $skipped];
    }

    /**
     * LEGACY step 1, executed.
     *
     * @return string[] executed statements
     */
    public function updateSchema(): array
    {
        $run = $this->schemaUpdatePlan()['run'];
        $connection = $this->em->getConnection();
        foreach ($run as $sql) {
            $connection->executeStatement($sql);
        }

        return $run;
    }

    /**
     * LEGACY step 2 (doctrine:migrations:version --add --all): record every
     * available migration as executed. Right after updateSchema() the
     * database matches the entities, i.e. the state after all of them.
     *
     * @return string[] versions recorded
     */
    public function markAllExecuted(): array
    {
        $storage = $this->migrations->getMetadataStorage();
        $storage->ensureInitialized();
        $marked = [];
        foreach ($this->migrations->getMigrationStatusCalculator()->getNewMigrations()->getItems() as $migration) {
            $storage->complete(new ExecutionResult($migration->getVersion(), Direction::UP, new \DateTimeImmutable()));
            $marked[] = (string)$migration->getVersion();
        }

        return $marked;
    }

    /**
     * Differences between the entities and the database that are not drops
     * (dropped legacy columns / foreign tables are not drift). Non-empty after
     * a migrate = an entity change without a migration.
     *
     * @return string[]
     */
    public function pendingSchemaChanges(): array
    {
        return array_values(array_filter($this->schemaUpdateSql(), fn($s) => !preg_match('/^\s*(ALTER TABLE \S+ DROP|DROP )/i', $s)));
    }

    /**
     * Serialize concurrent upgrades (two app replicas booting at once) with a
     * MySQL named lock. No-op on other platforms.
     */
    public function lock(int $timeoutSeconds = 600): bool
    {
        $connection = $this->em->getConnection();
        if (!$connection->getDatabasePlatform() instanceof AbstractMySQLPlatform) {
            return true;
        }

        return (int)$connection->fetchOne('SELECT GET_LOCK(?, ?)', [self::LOCK_NAME, $timeoutSeconds]) === 1;
    }

    public function unlock(): void
    {
        $connection = $this->em->getConnection();
        if ($connection->getDatabasePlatform() instanceof AbstractMySQLPlatform) {
            $connection->fetchOne('SELECT RELEASE_LOCK(?)', [self::LOCK_NAME]);
        }
    }

    public function migrationsTableName(): string
    {
        $config = $this->migrations->getConfiguration()->getMetadataStorageConfiguration();

        return $config instanceof TableMetadataStorageConfiguration ? $config->getTableName() : 'doctrine_migration_versions';
    }

    /** @return string[] */
    public function entityTables(): array
    {
        $schema = (new SchemaTool($this->em))->getSchemaFromMetadata($this->em->getMetadataFactory()->getAllMetadata());

        return array_map(fn($table) => $table->getObjectName()->toString(), $schema->getTables());
    }

    /** @return string[] SQL doctrine:schema:update would run, without statements on the migrations table */
    private function schemaUpdateSql(): array
    {
        $sql = (new SchemaTool($this->em))->getUpdateSchemaSql($this->em->getMetadataFactory()->getAllMetadata());
        $table = $this->migrationsTableName();

        return array_values(array_filter($sql, fn(string $s) => stripos($s, $table) === false));
    }

    /**
     * Case-insensitive intersection (MySQL table names follow the file system).
     *
     * @param string[] $a
     * @param string[] $b
     * @return string[] items of $a that are in $b
     */
    private static function intersect(array $a, array $b): array
    {
        $lower = array_map('strtolower', $b);

        return array_values(array_filter($a, fn(string $t) => in_array(strtolower($t), $lower, true)));
    }
}
