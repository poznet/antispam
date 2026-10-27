<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use AntispamBundle\Services\ImpersonationAnalyzer;
use AntispamBundle\Services\UrlAnalyzer;
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
    }
}
