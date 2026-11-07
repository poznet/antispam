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
final class Version20261107120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'YubiKey (Yubico OTP) login: antispam_yubikey - registered keys of panel users';
    }

    public function up(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql(<<<'SQL'
            CREATE TABLE antispam_yubikey (
              id INT AUTO_INCREMENT NOT NULL,
              user_id INT NOT NULL,
              public_id VARCHAR(16) NOT NULL,
              name VARCHAR(100) NOT NULL,
              created_at DATETIME NOT NULL,
              last_used_at DATETIME DEFAULT NULL,
              INDEX IDX_EE91E888A76ED395 (user_id),
              UNIQUE INDEX uniq_antispam_yubikey_public_id (public_id),
              PRIMARY KEY (id)
            ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci`
        SQL);
        $this->addSql(<<<'SQL'
            ALTER TABLE
              antispam_yubikey
            ADD
              CONSTRAINT FK_EE91E888A76ED395 FOREIGN KEY (user_id) REFERENCES antispam_user (id) ON DELETE CASCADE
        SQL);
    }

    public function down(Schema $schema): void
    {
        $this->abortIf(!$this->connection->getDatabasePlatform() instanceof AbstractMySQLPlatform, 'Antispam migrations support MySQL / MariaDB only.');

        $this->addSql('ALTER TABLE antispam_yubikey DROP FOREIGN KEY FK_EE91E888A76ED395');
        $this->addSql('DROP TABLE antispam_yubikey');
    }

    public function isTransactional(): bool
    {
        return false;
    }
}
