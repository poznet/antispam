<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\UrlAnalyzer;
use PHPUnit\Framework\TestCase;

class UrlAnalyzerTest extends TestCase
{
    private function rules(array $result)
    {
        return array_map(function ($r) { return strtok($r['rule'], ':'); }, $result['reasons']);
    }

    private function offline()
    {
        return new UrlAnalyzer(function () { return []; });
    }

    public function testPhishingHeuristics()
    {
        $html = '<a href="http://evil-login.ru/pko">www.pkobp.pl</a>'
            . '<a href=\'http://192.168.1.5/x\'>tu</a>'
            . '<a href=https://bit.ly/abc>skrót</a>'
            . '<a href="https://xn--pkobp-4ua.pl/">bank</a>';
        $r = $this->offline()->analyze($html, '', ['dbl_enabled' => false]);
        $this->assertSame(['url_text_mismatch', 'url_ip_host', 'url_shortener', 'url_punycode'], $this->rules($r));
        $this->assertSame(3 + 3 + 2 + 3, $r['score']);
    }

    public function testMatchingLinkTextIsClean()
    {
        $html = '<a href="https://www.firma.pl/oferta?utm=x">firma.pl</a> <a href="https://firma.pl">Kliknij tutaj</a>';
        $r = $this->offline()->analyze($html, 'Zobacz https://firma.pl/kontakt.', ['dbl_enabled' => false]);
        $this->assertSame(0, $r['score']);
        $this->assertSame(['firma.pl'], $r['domains']);
    }

    public function testRulesFireOncePerMessage()
    {
        $html = str_repeat('<a href="https://bit.ly/x">x</a>', 20);
        $this->assertSame(2, $this->offline()->analyze($html, '', ['dbl_enabled' => false])['score']);
    }

    public function testDblListingAndErrorCodes()
    {
        $resolver = function ($fqdn) {
            $map = [
                'evil.ru.dbl.spamhaus.org' => ['127.0.1.2'],
                'refused.com.dbl.spamhaus.org' => ['127.255.255.254'],
                'refused.com.multi.uribl.com' => ['127.0.0.1'],
            ];
            return $map[$fqdn] ?? [];
        };
        $a = new UrlAnalyzer($resolver);
        $zones = UrlAnalyzer::parseZones("dbl.spamhaus.org 6\nmulti.uribl.com 5");
        $r = $a->analyze('', 'http://www.evil.ru/x https://refused.com', ['dbl_zones' => $zones]);
        $this->assertSame(['url_dbl'], $this->rules($r));
        $this->assertSame('evil.ru', $r['reasons'][0]['domain']);

        $clean = $a->analyze('', 'https://refused.com', ['dbl_zones' => $zones]);
        $this->assertSame(0, $clean['score']);
    }

    public function testSafeBrowsingHook()
    {
        $a = new UrlAnalyzer(function () { return []; }, function (array $urls, $key) {
            return $key === 'k' ? [$urls[0]] : [];
        });
        $r = $a->analyze('', 'https://malware.test/x', ['dbl_enabled' => false, 'gsb_enabled' => true, 'gsb_api_key' => 'k']);
        $this->assertSame(['url_safebrowsing'], $this->rules($r));
        $this->assertSame(10, $r['score']);
    }

    public function testParseZones()
    {
        $this->assertSame(
            [['zone' => 'dbl.spamhaus.org', 'score' => 7], ['zone' => 'multi.surbl.org', 'score' => 6]],
            UrlAnalyzer::parseZones("dbl.spamhaus.org|7\n# comment\nnot a zone!\nmulti.surbl.org")
        );
    }
}
