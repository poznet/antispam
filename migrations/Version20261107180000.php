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
final class Version20261107180000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'YubiKeys of the built-in ADMIN_USER: antispam_yubikey.user_id nullable + admin_login';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql(<<<'SQL'
            ALTER TABLE
              antispam_yubikey
            ADD
              admin_login VARCHAR(180) DEFAULT NULL,
            CHANGE
              user_id user_id INT DEFAULT NULL
        SQL);
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql('DELETE FROM antispam_yubikey WHERE user_id IS NULL');
        $this->addSql(<<<'SQL'
            ALTER TABLE
              antispam_yubikey
            DROP
              admin_login,
            CHANGE
              user_id user_id INT NOT NULL
        SQL);
    }

    public function isTransactional(): bool
    {
        return false;
    }
}
