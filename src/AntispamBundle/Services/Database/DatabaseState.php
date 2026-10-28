<?php

namespace AntispamBundle\Services\Database;

/**
 * Snapshot of the database as antispam:db:upgrade sees it (DatabaseUpgrader::inspect()).
 */
final class DatabaseState
{
    /** No antispam table yet: run every migration (baseline included). */
    public const FRESH = 'fresh';
    /** Antispam tables but no executed migration: created by doctrine:schema:update (before 2.x migrations). */
    public const LEGACY = 'legacy';
    /** At least one migration recorded: just run the new ones. */
    public const MIGRATED = 'migrated';

    /**
     * @param string   $state            FRESH, LEGACY or MIGRATED
     * @param string[] $antispamTables   existing tables that belong to the entity mapping
     * @param string[] $foreignTables    existing tables the mapping does not know (left alone by migrations)
     * @param string[] $executed         versions recorded in the migrations table
     * @param string[] $pending          available versions not executed yet, in execution order
     * @param string[] $unknownExecuted  executed versions this code does not ship (the database is newer than the image)
     */
    public function __construct(
        public readonly string $state,
        public readonly array $antispamTables,
        public readonly array $foreignTables,
        public readonly bool $migrationsTableExists,
        public readonly array $executed,
        public readonly array $pending,
        public readonly array $unknownExecuted,
    ) {
    }
}
