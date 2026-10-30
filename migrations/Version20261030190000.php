<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Written by hand in the doctrine:migrations:diff format (one TEXT column,
 * same type as last_rescan_result) - review before committing
 * (docs/migrations.md). MySQL / MariaDB only.
 */
final class Version20261030190000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Full mailbox rescan: progress of an unfinished rescan on antispam_account, so a new rescan continues from it';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql(<<<'SQL'
            ALTER TABLE
              antispam_account
            ADD
              rescan_progress LONGTEXT DEFAULT NULL
        SQL);
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql(<<<'SQL'
            ALTER TABLE
              antispam_account
            DROP
              rescan_progress
        SQL);
    }

    public function isTransactional(): bool
    {
        return false;
    }
}
