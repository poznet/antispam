<?php

namespace AntispamBundle\Tests\Services\Backup;

use AntispamBundle\Command\ExportCommand;
use AntispamBundle\Command\ImportCommand;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Services\Backup\BackupFormat;
use AntispamBundle\Services\Backup\InvalidBackupException;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

class BackupFormatAndCommandsTest extends BackupTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/antispam-backup-test-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            unlink($f);
        }
        rmdir($this->dir);
    }

    public static function invalidDocuments(): array
    {
        $ok = ['format' => BackupFormat::FORMAT, 'schema_version' => 1];

        return [
            'not json' => ['{"format": ', 'Not a valid JSON'],
            'other json' => ['{"hello": "world"}', 'Not an antispam backup'],
            'json list' => ['[1,2,3]', 'Not an antispam backup'],
            'no schema version' => [json_encode(['format' => BackupFormat::FORMAT]), 'schema_version'],
            'string schema version' => [json_encode(['format' => BackupFormat::FORMAT, 'schema_version' => '1']), 'schema_version'],
            'newer schema' => [json_encode(['format' => BackupFormat::FORMAT, 'schema_version' => BackupFormat::SCHEMA_VERSION + 1]), 'newer than this application'],
            'accounts not a list' => [json_encode($ok + ['accounts' => ['email' => 'x']]), 'list of objects'],
            'rules list of scalars' => [json_encode($ok + ['rules' => ['blacklist' => ['a', 'b']]]), 'Rule list'],
            'settings a list' => [json_encode($ok + ['settings' => [1, 2]]), 'must be an object'],
        ];
    }

    #[DataProvider('invalidDocuments')]
    public function testInvalidFileIsRejected(string $json, string $message)
    {
        $this->expectException(InvalidBackupException::class);
        $this->expectExceptionMessage($message);
        BackupFormat::decode($json);
    }

    public function testZipRoundTrip()
    {
        $em = self::em();
        self::seed($em);
        $json = BackupFormat::encode(self::exporter($em)->export(false));
        file_put_contents($this->dir . '/b.zip', BackupFormat::zip($json));
        file_put_contents($this->dir . '/b.json', $json);

        $this->assertSame(BackupFormat::readFile($this->dir . '/b.json'), BackupFormat::readFile($this->dir . '/b.zip'));
    }

    public function testZipWithoutBackupEntryIsRejected()
    {
        $zip = new \ZipArchive();
        $zip->open($this->dir . '/x.zip', \ZipArchive::CREATE);
        $zip->addFromString('other.txt', 'x');
        $zip->close();

        $this->expectException(InvalidBackupException::class);
        BackupFormat::readFile($this->dir . '/x.zip');
    }

    public function testParseOnly()
    {
        $this->assertSame(BackupFormat::SECTIONS, BackupFormat::parseOnly(null));
        $this->assertSame(['rules', 'users'], BackupFormat::parseOnly('Rules,users,rules'));
        $this->expectException(InvalidBackupException::class);
        BackupFormat::parseOnly('rules,phishing');
    }

    public function testExportAndImportCommands()
    {
        $source = self::em();
        self::seed($source);
        $file = $this->dir . '/backup.json';

        $export = new CommandTester(new ExportCommand(self::exporter($source)));
        $this->assertSame(Command::SUCCESS, $export->execute(['--output' => $file, '--include-secrets' => true]));
        $this->assertStringContainsString('contains secrets', $export->getDisplay());
        $this->assertSame(0600, fileperms($file) & 0777);
        $this->assertSame(Command::FAILURE, $export->execute(['--output' => $file]), 'no silent overwrite');

        $target = self::em();
        $import = new CommandTester(new ImportCommand(self::importer($target)));

        $this->assertSame(Command::SUCCESS, $import->execute(['file' => $file, '--dry-run' => true]));
        $this->assertStringContainsString('dry run', $import->getDisplay());
        $this->assertSame(0, self::rowCount($target, Account::class));

        $this->assertSame(Command::INVALID, $import->execute(['file' => $file, '--mode' => 'replace']), 'replace needs --confirm-replace');
        $this->assertSame(Command::INVALID, $import->execute(['file' => $file, '--mode' => 'wipe']));

        $this->assertSame(Command::SUCCESS, $import->execute(['file' => $file, '--only' => 'rules']));
        $this->assertSame(2, self::rowCount($target, Blacklist::class));
        $this->assertSame(0, self::rowCount($target, Account::class));

        $this->assertSame(Command::SUCCESS, $import->execute(['file' => $file, '--mode' => 'replace', '--confirm-replace' => true]));
        $this->assertSame(2, self::rowCount($target, Account::class));
        $this->assertStringContainsString('Import finished', $import->getDisplay());

        file_put_contents($this->dir . '/bad.json', '{"format":"something-else"}');
        $this->assertSame(Command::FAILURE, $import->execute(['file' => $this->dir . '/bad.json']));
        $this->assertStringContainsString('Invalid backup', $import->getDisplay());
        $this->assertSame(Command::FAILURE, $import->execute(['file' => $file, '--only' => 'phishing']));
    }

    public function testExportToStdout()
    {
        $em = self::em();
        self::seed($em);
        $tester = new CommandTester(new ExportCommand(self::exporter($em)));
        $tester->execute([], ['capture_stderr_separately' => true]);

        $data = BackupFormat::decode($tester->getDisplay());
        $this->assertCount(2, $data['accounts']);
        $this->assertStringContainsString('not included', $tester->getErrorOutput());
    }
}
