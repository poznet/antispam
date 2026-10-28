<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\CertHoleService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class CertHoleServiceTest extends TestCase
{
    public static function normalizeCases()
    {
        return [
            ['Example.COM', 'example.com'],
            ["  evil.pl\r", 'evil.pl'],
            ['evil.pl.', 'evil.pl'],
            ['*.evil.pl', 'evil.pl'],
            ['# comment', ''],
            ['', ''],
            ['localhost', ''],
            ['10.0.0.1', ''],
            ['bad domain.pl', ''],
            ['xn--pkobp-4ua.pl', 'xn--pkobp-4ua.pl'],
        ];
    }

    #[DataProvider('normalizeCases')]
    public function testNormalize($in, $out)
    {
        $this->assertSame($out, CertHoleService::normalizeDomain($in));
    }

    public function testIdnIsConvertedToPunycode()
    {
        if (!function_exists('idn_to_ascii')) {
            $this->markTestSkipped('intl missing');
        }
        $this->assertSame('xn--bcher-kva.example', CertHoleService::normalizeDomain('Bücher.example'));
    }

    public function testCandidatesCoverParentDomains()
    {
        $this->assertSame(['a.b.example.com', 'b.example.com', 'example.com'], CertHoleService::candidates('A.b.example.com'));
        $this->assertSame(['example.com'], CertHoleService::candidates('example.com'));
        $this->assertSame([], CertHoleService::candidates('com'));
    }

    public function testParseListDedupesAndSkipsJunk()
    {
        $this->assertSame(['a.pl', 'b.pl'], CertHoleService::parseList("a.pl\nB.pl\r\na.pl\n# x\n\nnot a domain\n1.2.3.4\n"));
    }

    public function testSanityCheck()
    {
        $this->assertNotNull(CertHoleService::sanityError(0, 0));
        $this->assertNotNull(CertHoleService::sanityError(50, 0));
        $this->assertNull(CertHoleService::sanityError(1000, 0));
        $this->assertNotNull(CertHoleService::sanityError(400, 1000));
        $this->assertNull(CertHoleService::sanityError(600, 1000));
        $this->assertNull(CertHoleService::sanityError(5000, 1000));
    }

    public function testHostExtraction()
    {
        $this->assertSame(['evil.pl', 'x.org'], CertHoleService::hostsFromAddressHeader('Jan <a@evil.pl>, b@x.org'));
        $hosts = CertHoleService::linkHosts('<a href="https://login.evil.pl/x">pko.pl</a>', 'see http://10.0.0.1/a and https://ok.com/');
        sort($hosts);
        $this->assertSame(['login.evil.pl', 'ok.com'], $hosts);
    }

    public function testAgentParity()
    {
        if (!defined('ANTISPAM_AGENT_LIBRARY')) {
            define('ANTISPAM_AGENT_LIBRARY', true);
        }
        require_once __DIR__ . '/../../Resources/agent/antispam-agent.php';
        foreach (['Example.COM', '*.evil.pl', 'evil.pl.', '# c', 'localhost', '1.2.3.4', 'bad domain.pl', 'a.b.c.d.pl'] as $in) {
            $this->assertSame(CertHoleService::normalizeDomain($in), \certNormalize($in), $in);
            $this->assertSame(CertHoleService::candidates($in), \certCandidates($in), $in);
        }
        $text = "a.pl\nB.pl\n# x\nfoo\n";
        $this->assertSame(CertHoleService::parseList($text), \certParseList($text));
        foreach ([[0, 0], [50, 0], [1000, 0], [400, 1000], [600, 1000]] as [$n, $c]) {
            $this->assertSame(CertHoleService::sanityError($n, $c) === null, \certSanityError($n, $c) === null);
        }
    }
}
