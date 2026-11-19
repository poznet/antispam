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
final class Version20261119120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Complex rules (AND / OR conditions): antispam_complex_rule';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql(<<<'SQL'
            CREATE TABLE antispam_complex_rule (
              id INT AUTO_INCREMENT NOT NULL,
              email VARCHAR(255) NOT NULL,
              name VARCHAR(120) NOT NULL,
              enabled TINYINT NOT NULL,
              action VARCHAR(16) NOT NULL,
              score INT NOT NULL,
              conditions LONGTEXT NOT NULL,
              counter INT NOT NULL,
              source VARCHAR(16) NOT NULL,
              created_by VARCHAR(255) DEFAULT NULL,
              created_at DATETIME NOT NULL,
              updated_at DATETIME NOT NULL,
              INDEX idx_complex_rule_email (email),
              PRIMARY KEY (id)
            ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci`
        SQL);
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql('DROP TABLE antispam_complex_rule');
    }
}
