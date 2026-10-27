<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\ImpersonationAnalyzer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class ImpersonationAnalyzerTest extends TestCase
{
    private function analyze($fromName, $fromEmail, $auth = '', $vips = "Jan Kowalski <jan@firma.pl>\nAnna Nowak")
    {
        $a = new ImpersonationAnalyzer();
        return $a->analyze(
            ['from_name' => $fromName, 'from_email' => $fromEmail, 'auth_results' => $auth],
            ['firma.pl'],
            ImpersonationAnalyzer::parseVips($vips)
        );
    }

    private function rules(array $result)
    {
        return array_map(function ($r) { return strtok($r['rule'], ':'); }, $result['reasons']);
    }

    public function testVipNameFromForeignAddressIsFlagged()
    {
        $r = $this->analyze('Jan Kowalski', 'jan.kowalski.ceo@gmail.com');
        $this->assertSame(['impersonation_vip'], $this->rules($r));
        $this->assertSame(8, $r['score']);
    }

    public function testVipNameMatchesReorderedAndWithDiacritics()
    {
        $this->assertSame(['impersonation_vip'], $this->rules($this->analyze('KOWALSKI Jan (CEO)', 'x@gmail.com')));
        $this->assertSame(['impersonation_vip'], $this->rules($this->analyze('Anna Nowak', 'anna@nowak-consulting.com')));
    }

    public function testVipFromListedAddressIsClean()
    {
        $this->assertSame(0, $this->analyze('Jan Kowalski', 'jan@firma.pl')['score']);
    }

    public function testVipWithoutAddressAcceptsAnyProtectedDomainAddress()
    {
        $this->assertSame(0, $this->analyze('Anna Nowak', 'a.nowak@firma.pl')['score']);
    }

    public function testSingleWordVipIsIgnored()
    {
        $this->assertSame([], ImpersonationAnalyzer::parseVips("Anna\n# comment\n"));
    }

    #[DataProvider('lookalikes')]
    public function testLookalikeDomains($sender, $why)
    {
        $r = $this->analyze('Biuro', 'biuro@' . $sender);
        $this->assertSame(['lookalike_domain'], $this->rules($r), $sender);
        $this->assertSame($why, $r['reasons'][0]['match']);
    }

    public static function lookalikes()
    {
        return [
            ['firrna.pl', 'homoglyph'],
            ['f1rma.pl', 'homoglyph'],
            ['firma.com', 'tld'],
            ['firma-pl.com', 'affix'],
            ['secure-firma.net', 'affix'],
            ['firma.pl.evil.com', 'subdomain'],
            ['frima.pl', 'typo'],
            ['xn--frma-lza.pl', 'homoglyph'], // fırma.pl (dotless i)
            ['xn--frm-8cd1q.pl', 'homoglyph'], // fіrmа.pl (Cyrillic і, а)
        ];
    }

    public function testUnrelatedAndOwnSubdomainsAreClean()
    {
        $this->assertSame(0, $this->analyze('Biuro', 'biuro@mail.firma.pl')['score']);
        $this->assertSame(0, $this->analyze('Shop', 'news@allegro.pl')['score']);
        $this->assertSame(0, $this->analyze('Firmament', 'x@firmament.pl')['score']);
    }

    public function testEmbeddedAddressInDisplayName()
    {
        $this->assertSame(['display_name_embedded_address'], $this->rules($this->analyze('"office@other.com"', 'x@evil.com')));
        $this->assertSame(['impersonation_display_address'], $this->rules($this->analyze('jan@firma.pl', 'x@evil.com')));
        $this->assertSame(0, $this->analyze('x@evil.com', 'x@evil.com')['score']);
    }

    public function testOwnDomainSpoofNeedsExplicitAuthFailure()
    {
        $this->assertSame(['internal_domain_spoof'], $this->rules($this->analyze('Biuro', 'biuro@firma.pl', 'mx; spf=fail smtp.mailfrom=firma.pl; dmarc=fail')));
        $this->assertSame(0, $this->analyze('Biuro', 'biuro@firma.pl', 'mx; spf=pass; dmarc=pass')['score']);
        $this->assertSame(0, $this->analyze('Biuro', 'biuro@firma.pl', '')['score']);
    }

    public function testParseDomainsNormalises()
    {
        $this->assertSame(['firma.pl', 'firma.com'], ImpersonationAnalyzer::parseDomains("Firma.PL\n firma.com, firma.pl\nnodot"));
    }
}
