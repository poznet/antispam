<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\DigestTokenService;
use AntispamBundle\Services\QuarantineDigestService;
use PHPUnit\Framework\TestCase;

class DigestTokenServiceTest extends TestCase
{
    public function testRoundTrip()
    {
        $s = new DigestTokenService('secret');
        $t = $s->create('ssh-3', '1700000001.M1P2.host,S=123', 'whitelist', 3600, ['sender' => 'a@b.pl', 'subject' => 'Zażółć']);
        $this->assertSame(1, preg_match('/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/', $t));
        $d = $s->verify($t);
        $this->assertSame('ssh-3', $d['mailbox']);
        $this->assertSame('1700000001.M1P2.host,S=123', $d['id']);
        $this->assertSame('whitelist', $d['action']);
        $this->assertSame('Zażółć', $d['subject']);
    }

    public function testCarriesAccountBinding()
    {
        $s = new DigestTokenService('secret');
        $this->assertSame('jan@firma.pl', $s->verify($s->create('imap-5', '7', 'release', 3600, ['account' => 'Jan@Firma.pl']))['account']);
        $this->assertNull($s->verify($s->create('imap-5', '7', 'release', 3600))['account']);
    }

    public function testRejectsTamperedForeignAndExpired()
    {
        $s = new DigestTokenService('secret');
        $t = $s->create('imap', '42', 'release', 3600);
        list($body, $sig) = explode('.', $t);

        $forged = rtrim(strtr(base64_encode(json_encode(['m' => 'imap', 'i' => '43', 'a' => 'delete', 'e' => time() + 3600])), '+/', '-_'), '=');
        $this->assertNull($s->verify($forged . '.' . $sig));
        $this->assertNull((new DigestTokenService('other'))->verify($t));
        $this->assertNull($s->verify($s->create('imap', '42', 'release', -10)));
        $this->assertNull($s->verify('garbage'));
        $this->assertNull($s->verify($body . '.'));
    }

    public function testHighRiskReasonsBlockWhitelisting()
    {
        $this->assertTrue(QuarantineDigestService::isHighRisk([['rule' => 'lookalike_domain:a~b', 'score' => 6]]));
        $this->assertTrue(QuarantineDigestService::isHighRisk([['rule' => 'attachment_office_macro', 'score' => 6]]));
        $this->assertFalse(QuarantineDigestService::isHighRisk([['rule' => 'dkim_fail', 'score' => 4], ['rule' => 'url_shortener:bit.ly', 'score' => 2]]));
    }

    public function testReasonLabelsAreOrderedAndDeduplicated()
    {
        $labels = QuarantineDigestService::reasonLabels([
            ['rule' => 'dkim_fail', 'score' => 4],
            ['rule' => 'suspicious_subject', 'score' => 3],
            ['rule' => 'all_caps_subject', 'score' => 3],
            ['rule' => 'impersonation_vip:Jan', 'score' => 8],
        ]);
        $this->assertSame(['Podszywa się pod chronioną osobę', 'Brak lub błędny podpis (DKIM)', 'Podejrzany temat'], $labels);
    }
}
