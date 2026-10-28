<?php

namespace AntispamBundle\Tests\Fixtures\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/** Platform-neutral stand-in for the baseline in DatabaseUpgraderTest (SQLite). */
final class Version20000101000000 extends AbstractMigration
{
    public function up(Schema $schema): void
    {
        $this->addSql('CREATE TABLE fixture_marker (id INTEGER NOT NULL, PRIMARY KEY (id))');
    }

    public function isTransactional(): bool
    {
        return false;
    }
}
