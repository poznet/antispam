<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Written by hand in the doctrine:migrations:diff format - review before
 * committing (docs/migrations.md). MySQL / MariaDB only.
 */
final class Version20261119180000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Account statistics: antispam_account_daily_stat (scan counters per account, day and kind)';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql(<<<'SQL'
            CREATE TABLE antispam_account_daily_stat (
              id INT AUTO_INCREMENT NOT NULL,
              account_id INT NOT NULL,
              day DATE NOT NULL,
              kind VARCHAR(16) NOT NULL,
              passes INT NOT NULL,
              checked INT NOT NULL,
              skipped INT NOT NULL,
              whitelisted INT NOT NULL,
              blacklisted INT NOT NULL,
              quarantined INT NOT NULL,
              moved_to_spam INT NOT NULL,
              move_failed INT NOT NULL,
              errors INT NOT NULL,
              updated_at DATETIME NOT NULL,
              UNIQUE INDEX uniq_account_day_kind (account_id, day, kind),
              PRIMARY KEY (id)
            ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci`
        SQL);
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql('DROP TABLE antispam_account_daily_stat');
    }
}
