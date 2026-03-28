<?php

namespace AntispamBundle\Tests\Agent;

use PHPUnit\Framework\TestCase;

class AgentScriptTest extends TestCase
{
    private $agentPath;
    private $tmpDir;
    private $maildirPath;
    private $dbPath;

    protected function setUp(): void
    {
        $this->agentPath = __DIR__ . '/../../Resources/agent/antispam-agent.php';

        if (!file_exists($this->agentPath)) {
            $this->markTestSkipped('Agent script not found');
        }

        $this->tmpDir = sys_get_temp_dir() . '/antispam_test_' . uniqid();
        mkdir($this->tmpDir, 0755, true);

        $this->maildirPath = $this->tmpDir . '/Maildir';
        mkdir($this->maildirPath . '/new', 0755, true);
        mkdir($this->maildirPath . '/cur', 0755, true);
        mkdir($this->maildirPath . '/tmp', 0755, true);

        $this->dbPath = $this->tmpDir . '/rules.sqlite';
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tmpDir)) {
            $this->removeDir($this->tmpDir);
        }
    }

    public function testVersionCommand()
    {
        $output = $this->runAgent('version');
        $data = json_decode($output, true);

        $this->assertNotNull($data);
        $this->assertArrayHasKey('version', $data);
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', $data['version']);
    }

    public function testTestCommand()
    {
        $output = $this->runAgent('test', ['--maildir=' . $this->maildirPath]);
        $data = json_decode($output, true);

        $this->assertNotNull($data);
        $this->assertTrue($data['success']);
        $this->assertArrayHasKey('version', $data);
        $this->assertEquals('yes', $data['checks']['maildir_exists']);
    }

    public function testImportRulesAndScan()
    {
        // First create a test email in Maildir/new
        $emailContent = "From: spammer@evil-domain.com\r\nTo: test@example.com\r\nSubject: Buy now!\r\n\r\nSpam body";
        file_put_contents($this->maildirPath . '/new/test-msg-001', $emailContent);

        $whiteEmail = "From: friend@good-domain.com\r\nTo: test@example.com\r\nSubject: Hello\r\n\r\nHi!";
        file_put_contents($this->maildirPath . '/new/test-msg-002', $whiteEmail);

        // Import rules with blacklist
        $rules = json_encode([
            'whitelist' => [['email' => 'test@example.com', 'host' => 'good-domain.com']],
            'email_whitelist' => [],
            'blacklist' => [['email' => 'test@example.com', 'host' => 'evil-domain.com']],
            'email_blacklist' => [],
        ]);

        $output = $this->runAgent('import-rules', ['--db=' . $this->dbPath], $rules);
        $importResult = json_decode($output, true);

        $this->assertNotNull($importResult);
        $this->assertTrue($importResult['success']);
        $this->assertEquals(1, $importResult['imported']['whitelist']);
        $this->assertEquals(1, $importResult['imported']['blacklist']);

        // Run scan
        $output = $this->runAgent('scan', ['--maildir=' . $this->maildirPath, '--db=' . $this->dbPath]);
        $scanResult = json_decode($output, true);

        $this->assertNotNull($scanResult);
        $this->assertEquals(2, $scanResult['total']);
        $this->assertEquals(2, $scanResult['checked']);
        $this->assertEquals(1, $scanResult['whitelisted']);
        $this->assertEquals(1, $scanResult['blacklisted']);
        $this->assertEquals(1, $scanResult['moved_to_spam']);

        // Verify file was moved to SPAM folder
        $this->assertFalse(file_exists($this->maildirPath . '/new/test-msg-001'));
        $this->assertTrue(file_exists($this->maildirPath . '/.SPAM/new/test-msg-001'));

        // Whitelisted message should remain
        $this->assertTrue(file_exists($this->maildirPath . '/new/test-msg-002'));
    }

    public function testScanSkipsAlreadyChecked()
    {
        $emailContent = "From: someone@unknown.com\r\nTo: test@example.com\r\nSubject: Hi\r\n\r\nBody";
        file_put_contents($this->maildirPath . '/new/test-msg-003', $emailContent);

        // First scan
        $this->runAgent('import-rules', ['--db=' . $this->dbPath], json_encode([
            'whitelist' => [], 'email_whitelist' => [], 'blacklist' => [], 'email_blacklist' => [],
        ]));

        $output1 = $this->runAgent('scan', ['--maildir=' . $this->maildirPath, '--db=' . $this->dbPath]);
        $result1 = json_decode($output1, true);
        $this->assertEquals(1, $result1['checked']);
        $this->assertEquals(0, $result1['skipped']);

        // Second scan - same message should be skipped
        $output2 = $this->runAgent('scan', ['--maildir=' . $this->maildirPath, '--db=' . $this->dbPath]);
        $result2 = json_decode($output2, true);
        $this->assertEquals(0, $result2['checked']);
        $this->assertEquals(1, $result2['skipped']);
    }

    public function testStatusCommand()
    {
        // Initialize DB first
        $this->runAgent('import-rules', ['--db=' . $this->dbPath], json_encode([
            'whitelist' => [['email' => 'a@b.com', 'host' => 'test.com']],
            'email_whitelist' => [],
            'blacklist' => [],
            'email_blacklist' => [],
        ]));

        $output = $this->runAgent('status', ['--maildir=' . $this->maildirPath, '--db=' . $this->dbPath]);
        $status = json_decode($output, true);

        $this->assertNotNull($status);
        $this->assertArrayHasKey('version', $status);
        $this->assertTrue($status['db_exists']);
        $this->assertEquals(1, $status['rules']['whitelist']);
    }

    private function runAgent($command, $args = [], $stdin = null)
    {
        $cmd = 'php ' . escapeshellarg($this->agentPath) . ' ' . escapeshellarg($command);
        foreach ($args as $arg) {
            $cmd .= ' ' . escapeshellarg($arg);
        }

        $descriptors = [
            0 => $stdin !== null ? ['pipe', 'r'] : ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($cmd, $descriptors, $pipes);

        if ($stdin !== null) {
            fwrite($pipes[0], $stdin);
            fclose($pipes[0]);
        }

        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        return $output;
    }

    private function removeDir($dir)
    {
        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($files as $file) {
            if ($file->isDir()) {
                rmdir($file->getRealPath());
            } else {
                unlink($file->getRealPath());
            }
        }
        rmdir($dir);
    }
}
