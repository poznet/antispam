<?php

namespace AntispamBundle\Tests\Services;

use PHPUnit\Framework\TestCase;

/**
 * Runs the Maildir agent's scan / import / quarantine functions against a
 * scratch Maildir and SQLite database (no network: DNS, URL and CERT checks
 * are switched off in the synced settings).
 */
class AgentMaildirTest extends TestCase
{
    private $dir;

    public static function setUpBeforeClass(): void
    {
        if (!extension_loaded('sqlite3')) {
            self::markTestSkipped('sqlite3 extension required');
        }
        if (!defined('ANTISPAM_AGENT_LIBRARY')) {
            define('ANTISPAM_AGENT_LIBRARY', true);
        }
        require_once __DIR__ . '/../../Resources/agent/antispam-agent.php';
    }

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/antispam-agent-' . bin2hex(random_bytes(4));
        foreach (['Maildir/new', 'Maildir/cur', 'Maildir/tmp', 'agent'] as $d) {
            mkdir($this->dir . '/' . $d, 0700, true);
        }
    }

    protected function tearDown(): void
    {
        @chmod($this->dir . '/Maildir/.SPAM/new', 0700);
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($this->dir);
    }

    private function db()
    {
        return $this->dir . '/agent/rules.sqlite';
    }

    private function maildir()
    {
        return $this->dir . '/Maildir';
    }

    private function import(array $rules)
    {
        $rules += ['whitelist' => [], 'email_whitelist' => [], 'blacklist' => [], 'email_blacklist' => [], 'dnsbl' => []];
        $rules['settings'] = ($rules['settings'] ?? []) + [
            'url_enabled' => '0', 'cert_enabled' => '0', 'dnsbl_enabled' => '0',
            'impersonation_enabled' => '0', 'attachment_policy_enabled' => '0',
        ];
        return \importRules($this->db(), json_encode($rules));
    }

    private function put($path, $raw)
    {
        file_put_contents($this->maildir() . '/' . $path, $raw);
    }

    public function testThresholdsComeFromTheSyncedSettings()
    {
        $this->import([
            'email_blacklist' => [['email' => 'me@firma.pl', 'blacklistemail' => 'a@spam.pl', 'pattern_type' => 'exact', 'score' => 4]],
            'settings' => ['spam_threshold' => '4', 'quarantine_threshold' => '2'],
        ]);
        $this->put('new/1.M1.host', "From: a@spam.pl\nMessage-ID: <1@x>\nSubject: hi\n\nbody\n");

        $res = \runScan($this->maildir(), $this->db(), []);
        $this->assertSame(1, $res['moved_to_spam'], json_encode($res));
        $this->assertSame(4, $res['spam_threshold']);
        $this->assertFileExists($this->maildir() . '/.SPAM/new/1.M1.host');
        $this->assertFileExists($this->maildir() . '/.SPAM/maildirfolder');
    }

    public function testDisplayNameAddressDoesNotWhitelist()
    {
        $this->import([
            'whitelist' => [['email' => 'me@firma.pl', 'host' => 'firma.pl', 'pattern_type' => 'exact']],
            'email_blacklist' => [['email' => 'me@firma.pl', 'blacklistemail' => 'attacker@evil.com', 'pattern_type' => 'exact', 'score' => 10]],
        ]);
        $this->put('new/1.M1.host', "From: \"ceo@firma.pl\"\n <attacker@evil.com>\nSender: x@firma.pl\nMessage-ID: <1@x>\nSubject: pay\n\nbody\n");

        $res = \runScan($this->maildir(), $this->db(), []);
        $this->assertSame('spam', $res['decisions'][0]['decision']);
        $this->assertSame(0, $res['whitelisted']);
    }

    public function testFailedMoveIsRetriedAndLowercaseFlagsDoNotRescan()
    {
        $this->import(['email_blacklist' => [['email' => 'me@firma.pl', 'blacklistemail' => 'a@spam.pl', 'pattern_type' => 'exact', 'score' => 10]]]);
        $this->put('new/1.M1.host', "From: a@spam.pl\nMessage-ID: <1@x>\nSubject: hi\n\nbody\n");
        $this->put('cur/2.M1.host:2,S', "From: ok@good.pl\nMessage-ID: <2@x>\nSubject: hello\n\nbody\n");
        \ensureFolder($this->maildir() . '/.SPAM');
        chmod($this->maildir() . '/.SPAM/new', 0500);

        $res = \runScan($this->maildir(), $this->db(), []);
        if (is_writable($this->maildir() . '/.SPAM/new')) {
            $this->markTestSkipped('running as root: directory permissions are not enforced');
        }
        $this->assertSame(1, $res['move_failed']);
        $this->assertSame(0, $res['moved_to_spam']);
        $this->assertFileExists($this->maildir() . '/new/1.M1.host');

        chmod($this->maildir() . '/.SPAM/new', 0700);
        // Dovecot adds keyword flags (lower-case letters) to the ham message.
        rename($this->maildir() . '/cur/2.M1.host:2,S', $this->maildir() . '/cur/2.M1.host:2,Sab');

        $res = \runScan($this->maildir(), $this->db(), []);
        $this->assertSame(1, $res['moved_to_spam']);
        $this->assertSame(1, $res['skipped'], 'flag change must not re-scan the message');
        $this->assertFileExists($this->maildir() . '/.SPAM/new/1.M1.host');
    }

    public function testIdsStoredByOlderAgentsStillCount()
    {
        $this->import([]);
        $db = \getDb($this->db());
        \markChecked($db, '3.M1.host:2,Sa'); // pre-3.0 agents kept lower-case flags in the id
        $db->close();
        $this->put('cur/3.M1.host:2,Sa', "From: x@y.pl\nSubject: hi\n\nbody\n");

        $res = \runScan($this->maildir(), $this->db(), []);
        $this->assertSame(1, $res['skipped']);
        $this->assertSame(0, $res['checked']);
    }

    public function testMessageMovedFromNewToCurIsStillMoved()
    {
        $this->import([]);
        $this->put('cur/4.M1.host:2,S', "x");
        $res = \agentMoveMessage($this->maildir(), 'new', '4.M1.host', '.QUARANTINE');
        $this->assertTrue($res['ok'], (string)$res['error']);
        $this->assertFileExists($this->maildir() . '/.QUARANTINE/cur/4.M1.host:2,S');

        $res = \agentMoveMessage($this->maildir(), 'new', 'gone.M1.host', '.QUARANTINE');
        $this->assertFalse($res['ok']);
    }

    public function testImportIsAllOrNothing()
    {
        $this->assertTrue($this->import(['whitelist' => [['email' => 'me@firma.pl', 'host' => 'keep.pl']]])['success']);

        $bad = json_encode(['whitelist' => [['email' => 'me@firma.pl', 'host' => 'new.pl']], 'blacklist' => [['email' => 'me@firma.pl']]]);
        $res = \importRules($this->db(), $bad);
        $this->assertFalse($res['success']);
        $this->assertStringContainsString('previous rules kept', $res['error']);
        $this->assertSame('keep.pl', (new \SQLite3($this->db()))->querySingle('SELECT host FROM whitelist'));

        $this->assertFalse(\importRules($this->db(), '{"whitelist": "x"}')['success']);
        $this->assertFalse(\importRules($this->db(), "{'a':1}")['success']);
        $this->assertSame(0600, fileperms($this->db()) & 0777);
    }

    public function testPerAccountDatabaseIsSeededFromTheLegacyOne()
    {
        $this->import(['whitelist' => [['email' => 'me@firma.pl', 'host' => 'keep.pl']]]);
        $path = \agentDefaultDb($this->dir . '/agent', '7');
        $this->assertSame($this->dir . '/agent/rules-7.sqlite', $path);
        $this->assertSame('keep.pl', (new \SQLite3($path))->querySingle('SELECT host FROM whitelist'));
        $this->assertSame(0600, fileperms($path) & 0777);
        $this->assertSame($this->db(), \agentDefaultDb($this->dir . '/agent', null));
    }

    public function testQuarantineListSurvivesRawEightBitHeaders()
    {
        $this->import([]);
        mkdir($this->maildir() . '/.QUARANTINE/cur', 0700, true);
        file_put_contents($this->maildir() . '/.QUARANTINE/cur/9.M1.host:2,Sab', "From: \"Pawe\xB3\" <pawel@example.pl>\nSubject: Zam\xF3wienie\n\nbody\n");

        $res = \quarantineList($this->maildir(), $this->db(), []);
        $this->assertSame('9.M1.host', $res['items'][0]['id']);
        $json = \agentJson($res);
        $this->assertIsString($json);
        $decoded = json_decode($json, true);
        $this->assertSame('pawel@example.pl', $decoded['items'][0]['from']);
        $this->assertSame('Zam?wienie', $decoded['items'][0]['subject']);
    }

    public function testFoldedHeadersAreParsed()
    {
        $block = \readHeaderBlockFromString("From: Jan\n\t<jan@firma.pl>\nSubject: =?UTF-8?Q?Zam=C3=B3wienie?=\n =?UTF-8?Q?_nr_5?=\n\nbody");
        $parsed = \parseHeaders($block);
        $this->assertSame('jan@firma.pl', $parsed['sender_email']);
        $this->assertSame('Zamówienie nr 5', $parsed['subject']);
    }
}
