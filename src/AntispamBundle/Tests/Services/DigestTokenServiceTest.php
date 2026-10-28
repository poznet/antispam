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
        $this->assertSame('jan@firma.pl', $s->verify($s->create('imap-5', '7', 'release', 3600, ['account' => 'Jan@Firma.pl', 'uidvalidity' => 1]))['account']);
        $this->assertNull($s->verify($s->create('imap-5', '7', 'release', 3600, ['uidvalidity' => 1]))['account']);
    }

    public function testImapTokenCarriesUidValidity()
    {
        $s = new DigestTokenService('secret');
        $d = $s->verify($s->create('imap-5', '7', 'delete', 3600, ['uidvalidity' => '1700000123']));
        $this->assertSame(1700000123, $d['uidvalidity']);
        $this->assertSame(0, $s->verify($s->create('imap', '7', 'delete', 3600, ['uidvalidity' => 0]))['uidvalidity']);
    }

    /** Tokens minted before UIDVALIDITY binding: the UID may name another message now - reject. */
    public function testImapTokenWithoutUidValidityIsRejected()
    {
        $s = new DigestTokenService('secret');
        $this->assertNull($s->verify($s->create('imap', '42', 'release', 3600)));
        $this->assertNull($s->verify($s->create('imap-5', '42', 'whitelist', 3600, ['account' => 'jan@firma.pl'])));
        // Maildir file names are never reused: SSH tokens don't need it.
        $ssh = $s->verify($s->create('ssh-3', '1700000001.M1P2.host', 'release', 3600));
        $this->assertSame('ssh-3', $ssh['mailbox']);
        $this->assertNull($ssh['uidvalidity']);
    }

    public function testWeakSecretsCountAsDefault()
    {
        $this->assertTrue((new DigestTokenService('ChangeMeInProductionPlease'))->usesDefaultSecret());
        $this->assertTrue((new DigestTokenService('short'))->usesDefaultSecret());
        $this->assertTrue((new DigestTokenService('please-change-me-now-1234'))->usesDefaultSecret());
        $this->assertFalse((new DigestTokenService(bin2hex(random_bytes(16))))->usesDefaultSecret());
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
        // No score log row found: fail closed.
        $this->assertTrue(QuarantineDigestService::isHighRisk([['rule' => 'score_unknown', 'score' => 0]]));
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
