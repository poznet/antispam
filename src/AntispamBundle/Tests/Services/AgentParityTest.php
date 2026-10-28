<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\HeaderAnalyzer;
use AntispamBundle\Services\ImpersonationAnalyzer;
use AntispamBundle\Services\PatternMatcher;
use AntispamBundle\Services\RawMessageParser;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\UrlAnalyzer;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The standalone Maildir agent re-implements the web analyzers (it is
 * deployed as a single file). Feed both the same input and require the same
 * verdict, so the two pipelines can't drift apart silently.
 */
class AgentParityTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!defined('ANTISPAM_AGENT_LIBRARY')) {
            define('ANTISPAM_AGENT_LIBRARY', true);
        }
        require_once __DIR__ . '/../../Resources/agent/antispam-agent.php';
    }

    public static function impersonationCases()
    {
        return [
            ['Jan Kowalski', 'jan.kowalski.ceo@gmail.com', ''],
            ['Kowalski Jan', 'jan@firma.pl', ''],
            ['Anna Nowak', 'anna@nowak.com', ''],
            ['Biuro', 'biuro@firrna.pl', ''],
            ['Biuro', 'biuro@xn--frma-lza.pl', ''],
            ['Biuro', 'biuro@frima.pl', ''],
            ['Biuro', 'biuro@firma-pl.com', ''],
            ['Biuro', 'biuro@firma.pl.evil.com', ''],
            ['"jan@firma.pl"', 'x@evil.com', ''],
            ['"office@other.com"', 'x@evil.com', ''],
            ['Biuro', 'biuro@firma.pl', 'mx; spf=softfail; dmarc=fail'],
            ['Biuro', 'biuro@mail.firma.pl', 'mx; spf=pass'],
            ['Allegro', 'news@allegro.pl', ''],
        ];
    }

    #[DataProvider('impersonationCases')]
    public function testImpersonation($name, $email, $auth)
    {
        $vips = "Jan Kowalski <jan@firma.pl>\nAnna Nowak";
        $msg = ['from_name' => $name, 'from_email' => $email, 'auth_results' => $auth];

        $web = (new ImpersonationAnalyzer())->analyze($msg, ['firma.pl'], ImpersonationAnalyzer::parseVips($vips));
        $agent = \analyzeImpersonation($msg, ['firma.pl'], \parseVips($vips), []);

        $this->assertSame($web, $agent);
    }

    public function testUrls()
    {
        $html = '<a href="http://evil-login.ru/pko">www.pkobp.pl</a><a href="http://10.0.0.1/x">x</a>'
            . '<a href="https://bit.ly/q">q</a><a href="https://xn--pkobp-4ua.pl/">bank</a>'
            . '<a href="https://www.firma.pl/oferta">firma.pl</a>';
        $text = "Zobacz https://firma.pl/kontakt.\nhttp://t.co/abc";

        $web = (new UrlAnalyzer(function () { return []; }))->analyze($html, $text, ['dbl_enabled' => false]);
        $cache = [];
        $agent = \analyzeUrls($html, $text, \urlConfigFromSettings(['url_dbl_enabled' => '0']), null, $cache);

        unset($web['domains']);
        $this->assertSame($web, $agent);
        $this->assertGreaterThan(0, $web['score']);
    }

    public function testAttachmentPolicy()
    {
        $pe = 'MZ' . str_repeat("\0", 58) . pack('V', 64) . "PE\0\0" . str_repeat("\0", 32);
        $zip = "PK\x03\x04" . pack('vvvvvVVVvv', 20, 1, 0, 0, 0, 0, 3, 3, 8, 0) . 'evil.vbs' . 'abc';
        $attachments = [
            ['filename' => 'Faktura.pdf.exe', 'data' => 'x'],
            ['filename' => "utf-8''umowa%20Q3.pdf", 'data' => $pe],
            ['filename' => 'docs.zip', 'data' => $zip],
            ['filename' => "skan\u{202E}fdp.js", 'data' => 'x'],
            ['filename' => 'a.pdf', 'data' => "%PDF-1.4 /OpenAction << /S /Launch >>"],
        ];
        foreach ([$attachments, [$attachments[2]], [$attachments[4]], [['filename' => 'photo.jpg', 'data' => "\xFF\xD8\xFF"]]] as $set) {
            $web = (new AttachmentPolicyAnalyzer())->analyze($set);
            $agent = \analyzeAttachmentPolicy($set, \policyConfigFromSettings([]));
            $this->assertSame($web, $agent);
        }
    }

    public function testAgentDefaultsMatchWebDefaults()
    {
        $this->assertSame(AttachmentPolicyAnalyzer::DEFAULT_BLOCKED, \policyConfigFromSettings([])['blocked_extensions']);
        $url = \urlConfigFromSettings([]);
        foreach (['mismatch_score', 'ip_score', 'shortener_score', 'punycode_score', 'dbl_zones', 'max_domains', 'gsb_score', 'timeout'] as $k) {
            $this->assertSame(UrlAnalyzer::DEFAULT_CONFIG[$k], $url[$k], $k);
        }
        $this->assertSame(ScoringService::DEFAULT_SPAM_THRESHOLD, \AGENT_DEFAULT_SPAM_THRESHOLD);
        $this->assertSame(ScoringService::DEFAULT_QUARANTINE_THRESHOLD, \AGENT_DEFAULT_QUARANTINE_THRESHOLD);
        $this->assertSame(CertHoleService::DEFAULT_URL, \CERT_DEFAULT_URL);
    }

    public static function patternCases()
    {
        return [
            ['firma.pl', 'FIRMA.pl', 'exact'],
            ['Firma.PL', 'firma.pl', 'exact'],
            ['*.Evil.com', 'mx.evil.COM', 'wildcard'],
            ['ev?l.com', 'evil.com', 'wildcard'],
            ['a.b', 'axb', 'wildcard'],
            ['^\D+\.spam\.pl$', 'abc.spam.pl', 'regex'],     // \D must not become \d
            ['^\D+\.spam\.pl$', '123.spam.pl', 'regex'],
            ['^\S+@Firma\.pl$', 'jan@firma.pl', 'regex'],
            ['', 'x', 'exact'],
            ['x', '', 'exact'],
            ['x', 'x', null],
        ];
    }

    #[DataProvider('patternCases')]
    public function testPatternMatching($pattern, $value, $type)
    {
        $web = @PatternMatcher::match($pattern, $value, $type ?? PatternMatcher::EXACT);
        $this->assertSame($web, \patternMatch($pattern, $value, $type), "$type $pattern ~ $value");
    }

    public function testBrokenRegexNeverMatches()
    {
        $this->assertFalse(\patternMatch('(unclosed', 'x', 'regex'));
    }

    public static function fromCases()
    {
        return [
            ["From: jan@firma.pl\n"],
            ["From: Jan Kowalski <JAN@firma.pl>\n"],
            ["From: \"ceo@firma.pl\" <attacker@evil.com>\n"],          // display-name address
            ["From: ceo@firma.pl <attacker@evil.com>\n"],
            ["From: Jan\n <jan@firma.pl>\n"],                          // folded
            ["From: =?UTF-8?Q?Pawe=C5=82?= <pawel@example.pl>\n"],
            ["Sender: x@firma.pl\n"],                                   // no From: no sender
        ];
    }

    #[DataProvider('fromCases')]
    public function testSenderComesFromTheFromHeader($headers)
    {
        $raw = $headers . "Subject: x\n\nbody\n";
        $web = new RawMessageParser($raw);
        $agent = \parseHeaders(\readHeaderBlockFromString($raw));
        $this->assertSame($web->getFromAddress(), $agent['sender_email']);
        $this->assertSame($web->getFromHost(), $agent['sender_host']);
    }

    public function testDisplayNameCannotSmuggleTheSender()
    {
        $this->assertSame('attacker@evil.com', \extractEmail('"ceo@firma.pl" <attacker@evil.com>'));
        $this->assertSame('attacker@evil.com', \extractEmail('"a <ceo@firma.pl>" <attacker@evil.com>'));
        $this->assertSame('attacker@evil.com', \extractEmail('(ceo@firma.pl) attacker@evil.com'));
        $from = \parseFromHeader('"ceo@firma.pl" <attacker@evil.com>');
        $this->assertSame(['name' => 'ceo@firma.pl', 'email' => 'attacker@evil.com'], $from);
    }

    public static function receivedCases()
    {
        return [
            ["Received: from mail.evil.com (mail.evil.com [203.0.113.7]) by mx\n"],
            ["Received: from localhost (127.0.0.1) by mx\nReceived: from x ([10.1.2.3]) by y\nReceived: from z ([198.51.100.4]) by w\n"],
            ["Received: from a\n\tby mx with ESMTP id 1;\n\t(from [198.51.100.9])\n"],     // folded
            ["Received: from internal ([192.168.1.20]) by mx\n"],
        ];
    }

    #[DataProvider('receivedCases')]
    public function testConnectingIpSkipsPrivateHops($headers)
    {
        $raw = $headers . "From: a@b.pl\n\nbody\n";
        $this->assertSame((new RawMessageParser($raw))->getConnectingIp(), \extractConnectingIp(\readHeaderBlockFromString($raw)));
    }

    public static function headerCases()
    {
        $ok = "Message-ID: <a@b>\n";
        return [
            ["Authentication-Results: mx; spf=fail; dkim=pass; dmarc=pass\n" . $ok . "Subject: hello\n"],
            ["Authentication-Results: mx; spf=pass; dkim=fail; dmarc=pass\n" . $ok . "Subject: hello\n"],
            ["Received-SPF: fail (x)\n" . $ok . "Subject: hello\n"],
            ["From: a@one.pl\nReply-To: b@two.pl\n" . $ok . "Subject: hi\n"],
            ["From: a@one.pl\nReply-To: Name <b@one.pl>\n" . $ok . "Subject: hi\n"],
            ["Subject: GREAT OFFER NOW\n" . $ok],
            ["Subject: win \$\$\$ now\n" . $ok],
            ["Subject: You are a WINNER\n" . $ok],
            ["Subject: hello\n"],
            [str_repeat("Received: from x by y\n", 11) . $ok . "Subject: hello\n"],
        ];
    }

    /** Signals both implementations score the same way (no "none" results, one A-R header, cap off). */
    #[DataProvider('headerCases')]
    public function testHeaderHeuristics($headers)
    {
        $web = (new HeaderAnalyzer())->analyzeRaw($headers);
        $agent = \analyzeHeaders($headers, array_merge(\headerConfigFromSettings([]), ['cap' => -1]));
        $this->assertSame($web, $agent);
    }

    /**
     * Unsigned mail: dkim/dmarc "none" score 1-2 points, only the topmost
     * Authentication-Results counts and the header sub-score stays below the
     * quarantine threshold. Compared with HeaderAnalyzer once the web side
     * implements the same rules (review item 5).
     */
    public function testHeaderDefaultsForUnsignedAndForgedResults()
    {
        $q = ScoringService::DEFAULT_QUARANTINE_THRESHOLD;
        $unsigned = "Authentication-Results: mx; spf=pass; dkim=none; dmarc=none\nMessage-ID: <a@b>\nSubject: hi\n";
        $agent = \analyzeHeaders($unsigned, \headerConfigFromSettings([], $q));
        $this->assertGreaterThan(0, $agent['score']);
        $this->assertLessThanOrEqual(4, $agent['score']);
        foreach ($agent['reasons'] as $r) {
            $this->assertLessThanOrEqual(2, $r['score'], $r['rule']);
        }

        $forged = "Authentication-Results: mx; spf=fail; dkim=pass; dmarc=pass\nAuthentication-Results: evil; spf=pass\nMessage-ID: <a@b>\nSubject: hi\n";
        $this->assertSame([['rule' => 'spf_fail', 'score' => 6], ['rule' => 'header_score_cap', 'score' => $q - 1 - 6]], \analyzeHeaders($forged, \headerConfigFromSettings([], $q))['reasons']);
        $stale = "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\nAuthentication-Results: old-hop; spf=fail; dkim=fail\nMessage-ID: <a@b>\nSubject: hi\n";
        $this->assertSame(0, \analyzeHeaders($stale)['score']);

        $all = "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\nSubject: FREE MONEY NOW!!!\n";
        $this->assertSame($q - 1, \analyzeHeaders($all, \headerConfigFromSettings([], $q))['score']);

        $web = (new HeaderAnalyzer())->analyzeRaw($unsigned);
        if (in_array(['rule' => 'dkim_fail', 'score' => 4], $web['reasons'], true)) {
            $this->markTestIncomplete('HeaderAnalyzer still scores dkim=none as dkim_fail (review item 5 pending on the web side)');
        }
        foreach ([$unsigned, $forged, $stale, $all] as $h) {
            $this->assertSame($web = (new HeaderAnalyzer())->analyzeRaw($h), \analyzeHeaders($h, \headerConfigFromSettings([], $q)), $h);
        }
    }

    public function testDnsblAnswersOnlyListWithRealCodes()
    {
        $this->assertSame('listed', \dnsblClassify(['127.0.0.2']));
        $this->assertSame('listed', \dnsblClassify(['127.255.255.254', '127.0.0.4']));
        $this->assertSame('clean', \dnsblClassify([]));
        foreach ([['127.0.0.1'], ['127.255.255.254'], ['127.255.255.252'], ['198.51.100.1'], ['10.0.0.1']] as $ips) {
            $this->assertSame('error', \dnsblClassify($ips), implode(',', $ips));
        }
    }

    public function testDnsblErrorsAreNotCached()
    {
        $db = new \SQLite3(':memory:');
        $db->exec('CREATE TABLE dnsbl_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, zone TEXT, listed INTEGER, checked_at TEXT, UNIQUE(ip, zone))');
        $prov = ['zone' => 'zen.example', 'cache_ttl' => 3600];
        $calls = 0;
        $answer = null;
        $resolver = function ($fqdn) use (&$calls, &$answer) {
            $calls++;
            $this->assertSame('7.113.0.203.zen.example', $fqdn);
            return $answer;
        };

        $answer = ['127.255.255.254']; // public-resolver refusal
        $this->assertFalse(\dnsblLookup($db, '203.0.113.7', $prov, $resolver));
        $answer = null;                // resolver error
        $this->assertFalse(\dnsblLookup($db, '203.0.113.7', $prov, $resolver));
        $this->assertSame(0, $db->querySingle('SELECT COUNT(*) FROM dnsbl_cache'));

        $answer = ['127.0.0.2'];
        $this->assertTrue(\dnsblLookup($db, '203.0.113.7', $prov, $resolver));
        $this->assertTrue(\dnsblLookup($db, '203.0.113.7', $prov, $resolver)); // cached
        $this->assertSame(3, $calls);
    }

    public function testExportedSettingsDriveTheAgentThresholds()
    {
        $config = $this->createMock(ConfigService::class);
        $config->method('get')->willReturnMap([
            ['scoring.spam_threshold', '14'],
            ['scoring.quarantine_threshold', '7'],
            ['scoring.header_check_enabled', '0'],
            ['cert.url', 'https://example.test/list.txt'],
        ]);
        $scoring = new ScoringService($this->createMock(EntityManagerInterface::class), $config);
        // the agent stores settings as strings, booleans as '1' / '0'
        $settings = array_map(function ($v) { return is_bool($v) ? ($v ? '1' : '0') : (string)$v; }, $scoring->exportAgentSettings('me@firma.pl'));

        $cfg = \scanConfig($settings, []);
        $this->assertSame(14, $cfg['spam_threshold']);
        $this->assertSame(7, $cfg['quarantine_threshold']);
        $this->assertFalse($cfg['headers']);
        $this->assertTrue($cfg['dnsbl']);
        $this->assertSame('https://example.test/list.txt', \certUrlFromSettings($settings));
        $this->assertSame(16, \scanConfig($settings, ['spam-threshold' => '16'])['spam_threshold']);
        $this->assertSame('spam', \agentClassify(14, false, $cfg));
        $this->assertSame('quarantine', \agentClassify(7, false, $cfg));
        $this->assertSame('ham', \agentClassify(6, false, $cfg));

        $settings['scoring_enabled'] = '0';
        $off = \scanConfig($settings, []);
        $this->assertFalse($off['scoring']);
        $this->assertFalse($off['dnsbl'] || $off['urls'] || $off['impersonation'] || $off['policy']);
    }

    public function testMaildirIdIgnoresAllFlags()
    {
        $this->assertSame('1700000000.M1P2.host', \agentBaseId('1700000000.M1P2.host:2,Sab'));
        $this->assertSame('1700000000.M1P2.host', \agentBaseId('1700000000.M1P2.host:2,'));
        $this->assertSame('1700000000.M1P2.host', \agentBaseId('1700000000.M1P2.host'));
        $this->assertSame('1700000000.M1P2.host,S=123', \agentBaseId('1700000000.M1P2.host,S=123:2,FRS'));
        $this->assertSame('1700000000.M1P2.host:2,Sab', \agentLegacyId('1700000000.M1P2.host:2,Sab'));
    }
}
