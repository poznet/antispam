<?php

namespace AntispamBundle\Tests\Services;

use PHPUnit\Framework\TestCase;

/**
 * Agent 3.1 `spam-list` / `spam-release` against a scratch Maildir and SQLite
 * database (like AgentMaildirTest).
 */
class AgentSpamFolderTest extends TestCase
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
        $this->dir = sys_get_temp_dir() . '/antispam-agent-spam-' . bin2hex(random_bytes(4));
        foreach (['Maildir/new', 'Maildir/cur', 'Maildir/tmp', 'Maildir/.SPAM/new', 'Maildir/.SPAM/cur', 'agent'] as $d) {
            mkdir($this->dir . '/' . $d, 0700, true);
        }
    }

    protected function tearDown(): void
    {
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

    private function put($path, $raw, $mtime)
    {
        file_put_contents($this->maildir() . '/' . $path, $raw);
        touch($this->maildir() . '/' . $path, $mtime);
    }

    private function import(array $rules)
    {
        $rules += ['whitelist' => [], 'email_whitelist' => [], 'blacklist' => [], 'email_blacklist' => [], 'dnsbl' => []];
        $rules['settings'] = [
            'url_enabled' => '0', 'cert_enabled' => '0', 'dnsbl_enabled' => '0',
            'impersonation_enabled' => '0', 'attachment_policy_enabled' => '0',
        ];
        return \importRules($this->db(), json_encode($rules));
    }

    public function testSpamListIsNewestFirstAndLimited()
    {
        $this->put('.SPAM/cur/100.M1.host:2,S', "From: Old <old@spam.pl>\nSubject: stary\nDate: Mon, 1 Jan 2024 10:00:00 +0000\n\nx\n", time() - 3000);
        $this->put('.SPAM/new/200.M2.host', "From: \"Promo\" <promo@sklep.pl>\nSubject: =?UTF-8?B?UHJvbW9jamEgxbx5d2Vj?=\n\nx\n", time() - 100);
        $this->put('.SPAM/new/150.M3.host', "From: mid@spam.pl\nSubject: mid\n\nx\n", time() - 1000);
        $this->put('new/1.M9.host', "From: inbox@x.pl\nSubject: not spam\n\nx\n", time());

        $res = \spamList($this->maildir(), $this->db(), ['limit' => '2']);

        $this->assertTrue($res['success']);
        $this->assertSame(3, $res['total']);
        $this->assertSame(['200.M2.host', '150.M3.host'], array_column($res['items'], 'id'));
        $this->assertSame('promo@sklep.pl', $res['items'][0]['from']);
        $this->assertSame('Promo', $res['items'][0]['from_name']);
        $this->assertSame('Promocja żywec', $res['items'][0]['subject']);
        $this->assertNull($res['items'][0]['score']);
    }

    public function testSpamListCarriesTheScoreLogOfTheScan()
    {
        $this->import([
            'email_blacklist' => [['email' => 'me@firma.pl', 'blacklistemail' => 'a@spam.pl', 'pattern_type' => 'exact', 'score' => 10]],
        ]);
        $this->put('new/5.M5.host', "From: a@spam.pl\nMessage-ID: <5@x>\nSubject: buy\n\nbody\n", time());
        $scan = \runScan($this->maildir(), $this->db(), []);
        $this->assertSame(1, $scan['moved_to_spam'], json_encode($scan));

        $res = \spamList($this->maildir(), $this->db(), []);
        $this->assertSame('5.M5.host', $res['items'][0]['id']);
        $this->assertGreaterThanOrEqual(10, $res['items'][0]['score']);
        $this->assertNotEmpty($res['items'][0]['reasons']);
    }

    public function testSpamListOfAMissingFolderIsEmpty()
    {
        rmdir($this->maildir() . '/.SPAM/new');
        rmdir($this->maildir() . '/.SPAM/cur');
        $res = \spamList($this->maildir(), $this->db(), []);
        $this->assertSame(['success' => true, 'total' => 0, 'items' => []], $res);
    }

    public function testSpamReleaseMovesBackMarksCheckedAndIsNotRefiltered()
    {
        $this->import([
            'email_blacklist' => [['email' => 'me@firma.pl', 'blacklistemail' => 'a@spam.pl', 'pattern_type' => 'exact', 'score' => 10]],
        ]);
        $this->put('new/5.M5.host', "From: a@spam.pl\nMessage-ID: <5@x>\nSubject: buy\n\nbody\n", time());
        \runScan($this->maildir(), $this->db(), []);
        $this->assertFileExists($this->maildir() . '/.SPAM/new/5.M5.host');

        $res = \spamRelease($this->maildir(), $this->db(), ['id' => '5.M5.host']);
        $this->assertTrue($res['success'], json_encode($res));
        $this->assertSame('a@spam.pl', $res['sender']);
        $this->assertFalse($res['whitelisted']);
        $this->assertFileExists($this->maildir() . '/new/5.M5.host');
        $this->assertFileDoesNotExist($this->maildir() . '/.SPAM/new/5.M5.host');

        // The blacklist rule still matches, but the released message stays in INBOX.
        $again = \runScan($this->maildir(), $this->db(), []);
        $this->assertSame(0, $again['moved_to_spam'], json_encode($again));
        $this->assertFileExists($this->maildir() . '/new/5.M5.host');
    }

    public function testSpamReleaseKeepsTheMaildirFlagsAndCanWhitelist()
    {
        $this->put('.SPAM/cur/7.M7.host:2,S', "From: Szef <szef@firma.pl>\nSubject: hi\n\nx\n", time());
        $res = \spamRelease($this->maildir(), $this->db(), ['id' => '7.M7.host', 'whitelist' => true]);

        $this->assertTrue($res['success']);
        $this->assertTrue($res['whitelisted']);
        $this->assertFileExists($this->maildir() . '/cur/7.M7.host:2,S');
        $db = new \SQLite3($this->db());
        $this->assertSame(1, (int)$db->querySingle("SELECT COUNT(*) FROM email_whitelist WHERE whitelistemail = 'szef@firma.pl'"));
        $this->assertSame(1, (int)$db->querySingle("SELECT COUNT(*) FROM checked WHERE message_id = '7.M7.host'"));
    }

    public function testSpamReleaseRefusesBadAndUnknownIds()
    {
        $this->put('new/8.M8.host', "From: a@b.pl\n\nx\n", time());
        foreach (['', '../new/8.M8.host', 'a/b', '..', str_repeat('a', 300)] as $id) {
            $this->assertFalse(\spamRelease($this->maildir(), $this->db(), ['id' => $id])['success'], $id);
        }
        $res = \spamRelease($this->maildir(), $this->db(), ['id' => '8.M8.host']);
        $this->assertFalse($res['success'], 'INBOX message is not in SPAM');
        $this->assertStringContainsString('not found', $res['error']);
        // Quarantine commands do not see the SPAM folder either.
        $this->put('.SPAM/new/9.M9.host', "From: a@b.pl\n\nx\n", time());
        $this->assertFalse(\quarantineRelease($this->maildir(), $this->db(), ['id' => '9.M9.host'])['success']);
    }
}
