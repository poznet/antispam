<?php

declare(strict_types=1);

namespace Application\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20260328000001 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Add SSH key storage, sync tracking, and scan log table';
    }

    public function up(Schema $schema): void
    {
        // Add new columns to antispam_account
        $this->addSql('ALTER TABLE antispam_account ADD ssh_key_private LONGTEXT DEFAULT NULL');
        $this->addSql('ALTER TABLE antispam_account ADD ssh_key_passphrase VARCHAR(255) DEFAULT NULL');
        $this->addSql('ALTER TABLE antispam_account ADD needs_sync TINYINT(1) NOT NULL DEFAULT 0');
        $this->addSql('ALTER TABLE antispam_account ADD last_sync_at DATETIME DEFAULT NULL');

        // Create scan_log table
        $this->addSql('CREATE TABLE antispam_scan_log (
            id INT AUTO_INCREMENT NOT NULL,
            account_id INT DEFAULT NULL,
            scan_type VARCHAR(10) NOT NULL,
            scanned_at DATETIME NOT NULL,
            duration_ms INT DEFAULT NULL,
            total_messages INT NOT NULL DEFAULT 0,
            checked INT NOT NULL DEFAULT 0,
            skipped INT NOT NULL DEFAULT 0,
            whitelisted INT NOT NULL DEFAULT 0,
            blacklisted INT NOT NULL DEFAULT 0,
            moved_to_spam INT NOT NULL DEFAULT 0,
            success TINYINT(1) NOT NULL DEFAULT 1,
            error_message LONGTEXT DEFAULT NULL,
            result_json LONGTEXT DEFAULT NULL,
            INDEX IDX_SCAN_ACCOUNT (account_id),
            INDEX IDX_SCAN_DATE (scanned_at),
            PRIMARY KEY(id),
            CONSTRAINT FK_SCAN_ACCOUNT FOREIGN KEY (account_id) REFERENCES antispam_account (id) ON DELETE CASCADE
        ) DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci ENGINE = InnoDB');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE antispam_scan_log');
        $this->addSql('ALTER TABLE antispam_account DROP ssh_key_private');
        $this->addSql('ALTER TABLE antispam_account DROP ssh_key_passphrase');
        $this->addSql('ALTER TABLE antispam_account DROP needs_sync');
        $this->addSql('ALTER TABLE antispam_account DROP last_sync_at');
    }
}
