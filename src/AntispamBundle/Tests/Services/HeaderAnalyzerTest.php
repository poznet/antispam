<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\HeaderAnalyzer;
use AntispamBundle\Services\ScoringService;
use Ddeboer\Imap\MessageInterface;
use PHPUnit\Framework\TestCase;

class HeaderAnalyzerTest extends TestCase
{
    private static function block(array $lines)
    {
        return implode("\r\n", $lines) . "\r\n";
    }

    private static function rules(array $analysis)
    {
        $out = [];
        foreach ($analysis['reasons'] as $r) {
            $out[$r['rule']] = $r['score'];
        }
        return $out;
    }

    private function scoring($quarantine = 5, $spam = 10)
    {
        $s = $this->createMock(ScoringService::class);
        $s->method('getQuarantineThreshold')->willReturn($quarantine);
        $s->method('getSpamThreshold')->willReturn($spam);
        return $s;
    }

    public function testUnsignedLegitimateMailIsNotSpam()
    {
        $a = (new HeaderAnalyzer())->analyzeRaw(self::block([
            'Authentication-Results: mx.firma.pl; spf=pass smtp.mailfrom=sklep.pl; dkim=none; dmarc=none',
            'From: Sklep <biuro@sklep.pl>',
            'Subject: Potwierdzenie zamówienia',
            'Message-ID: <1@sklep.pl>',
        ]));

        $this->assertSame(['dkim_none' => 1, 'dmarc_none' => 1], self::rules($a));
        $this->assertSame(2, $a['score']);
    }

    public function testOnlyTheTopmostAuthenticationResultsCounts()
    {
        $block = self::block([
            'Authentication-Results: mx.firma.pl; spf=fail smtp.mailfrom=bank.pl; dkim=fail; dmarc=fail',
            'Authentication-Results: spammer.example; spf=pass; dkim=pass; dmarc=pass',
            'From: <x@bank.pl>',
            'Message-ID: <2@bank.pl>',
        ]);
        $this->assertSame(['spf_fail' => 6, 'dkim_fail' => 4, 'dmarc_fail' => 6], self::rules((new HeaderAnalyzer())->analyzeRaw($block)));

        // A stale "fail" below the receiving server's "pass" (forwarded mail) is ignored.
        $block = self::block([
            'Authentication-Results: mx.firma.pl; spf=pass; dkim=pass; dmarc=pass',
            'Authentication-Results: old-hop.example; spf=fail; dmarc=fail',
            'From: <x@bank.pl>',
            'Message-ID: <3@bank.pl>',
        ]);
        $this->assertSame(0, (new HeaderAnalyzer())->analyzeRaw($block)['score']);
    }

    public function testFoldedHeadersAreUnfolded()
    {
        $a = (new HeaderAnalyzer())->analyzeRaw(self::block([
            'Authentication-Results: mx.google.com;',
            '       dkim=pass header.i=@firma.pl;',
            '       spf=softfail (google.com: domain of transitioning x@firma.pl) smtp.mailfrom=x@firma.pl;',
            '       dmarc=fail (p=NONE) header.from=firma.pl',
            'From: <x@firma.pl>',
            'Message-ID: <4@firma.pl>',
        ]));
        $this->assertSame(['spf_fail' => 6, 'dmarc_fail' => 6], self::rules($a));
    }

    public function testOneGoodDkimSignatureWins()
    {
        $a = (new HeaderAnalyzer())->analyzeRaw(self::block([
            'Authentication-Results: mx; dkim=fail header.d=list.example; dkim=pass header.d=firma.pl; dmarc=pass',
            'From: <x@firma.pl>',
            'Message-ID: <5@firma.pl>',
        ]));
        $this->assertSame(0, $a['score']);
    }

    public function testHeaderScoreIsCapped()
    {
        $analyzer = new HeaderAnalyzer($this->scoring(5, 10));

        // Hard failures alone: at most spam threshold - 1 (quarantine, never SPAM).
        $a = $analyzer->analyzeRaw(self::block([
            'Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail',
            'From: <x@bank.pl>',
            'Message-ID: <6@bank.pl>',
        ]));
        $this->assertSame(9, $a['score']);
        $this->assertSame(-7, self::rules($a)['header_cap']);
        $this->assertSame($a['score'], array_sum(array_column($a['reasons'], 'score')));

        // Soft signals alone stay below the quarantine threshold.
        $a = $analyzer->analyzeRaw(self::block([
            'Authentication-Results: mx; spf=pass; dkim=none; dmarc=none',
            'From: <x@sklep.pl>',
            'Reply-To: <y@other.pl>',
            'Subject: =?UTF-8?B?UFJPTU9DSkEgVFlMS08gRFpJAZo=?= $$$',
        ]));
        $this->assertSame(4, $a['score']);
    }

    public function testSuspiciousSubject()
    {
        $this->assertFalse(HeaderAnalyzer::isSuspiciousSubject('FV 2025/10/0123'));
        $this->assertFalse(HeaderAnalyzer::isSuspiciousSubject('Re: PZU OC'));
        $this->assertTrue(HeaderAnalyzer::isSuspiciousSubject('PILNE WEZWANIE DO ZAPŁATY'));
        $this->assertTrue(HeaderAnalyzer::isSuspiciousSubject('Zarabiaj $$$ w domu'));
        $this->assertFalse(HeaderAnalyzer::isSuspiciousSubject('Faktura za październik'));
    }

    public function testEncodedSubjectIsDecodedBeforeHeuristics()
    {
        // "PILNE WEZWANIE DO ZAPŁATY" as an RFC 2047 word - lower-case base64 letters must not hide it.
        $subject = '=?UTF-8?B?' . base64_encode('PILNE WEZWANIE DO ZAPŁATY') . '?=';
        $a = (new HeaderAnalyzer())->analyzeRaw(self::block(['From: <x@a.pl>', 'Message-ID: <7@a.pl>', 'Subject: ' . $subject]));
        $this->assertArrayHasKey('suspicious_subject', self::rules($a));
    }

    public function testImapMessageUsesRawHeaders()
    {
        $msg = $this->createMock(MessageInterface::class);
        $msg->method('getRawHeaders')->willReturn(self::block([
            'Authentication-Results: mx; spf=fail; dmarc=fail',
            'From: <x@bank.pl>',
            'Message-ID: <8@bank.pl>',
        ]));
        $this->assertSame(['spf_fail' => 6, 'dmarc_fail' => 6], self::rules((new HeaderAnalyzer())->analyzeImap($msg)));
    }

    public function testTopmostAuthResults()
    {
        $this->assertSame('mx; spf=fail', HeaderAnalyzer::topmostAuthResults("Authentication-Results: mx;\r\n spf=fail\r\nAuthentication-Results: evil; spf=pass\r\n"));
        $this->assertSame('', HeaderAnalyzer::topmostAuthResults("From: a@b.c\r\n"));
    }
}
