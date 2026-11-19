<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\ComplexRuleEngine;
use AntispamBundle\Services\ComplexRuleMessage;
use AntispamBundle\Services\SenderIntelService;
use PHPUnit\Framework\TestCase;

class ComplexRuleEngineTest extends TestCase
{
    private const RAW = "Return-Path: <x@evil.ru>\r\n"
        . "Authentication-Results: mx.firma.pl; spf=softfail smtp.mailfrom=evil.ru; dkim=none; dmarc=fail\r\n"
        . "Authentication-Results: old.example; spf=pass\r\n"
        . "From: =?UTF-8?Q?Dzia=C5=82_Faktur?= <Faktury@Mail.Evil.RU>\r\n"
        . "To: Jan <jan@firma.pl>, anna@firma.pl\r\n"
        . "Cc: biuro@firma.pl\r\n"
        . "Subject: =?UTF-8?Q?Pilna_FAKTURA_nr_12/2026?=\r\n"
        . "X-Mailer: PHPMailer 6.1\r\n"
        . "List-Unsubscribe: <mailto:u@evil.ru>\r\n"
        . "Received: from relay.evil.ru (relay.evil.ru [203.0.113.7]) by mx.firma.pl\r\n"
        . "MIME-Version: 1.0\r\n"
        . "Content-Type: multipart/mixed; boundary=\"b1\"\r\n"
        . "\r\n"
        . "--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        . "<p>Prosimy o   zapłatę.</p><a href=\"https://pay.bad-link.top/x\">kliknij</a>\r\n"
        . "--b1\r\nContent-Type: application/octet-stream; name=\"faktura.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"faktura.pdf.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA\r\n"
        . "--b1--\r\n";

    private function msg(): ComplexRuleMessage
    {
        $intel = new SenderIntelService(null, null, fn ($d) => $d === 'mail.evil.ru' ? ['aspmx.l.google.com'] : [], fn ($d) => $d === 'evil.ru' ? 12 : null);
        return ComplexRuleMessage::fromRaw(self::RAW, $intel, 'jan@firma.pl');
    }

    private function eval(array $tree): bool
    {
        $norm = ComplexRuleEngine::normalize($tree, $errors);
        $this->assertNotNull($norm, implode(' ', $errors));
        return ComplexRuleEngine::evaluate($norm, $this->msg()->provider());
    }

    public function testFields()
    {
        $m = $this->msg();
        $this->assertSame(['faktury@mail.evil.ru'], $m->values('from'));
        $this->assertSame(['mail.evil.ru'], $m->values('from_domain'));
        $this->assertSame(['Dział Faktur'], $m->values('from_name'));
        $this->assertSame(['jan@firma.pl', 'anna@firma.pl', 'biuro@firma.pl'], $m->values('to'));
        $this->assertSame(['PHPMailer 6.1'], $m->values('header', 'x-mailer'));
        $this->assertSame(['faktura.pdf.exe'], $m->values('attachment'));
        $this->assertSame(['pay.bad-link.top'], $m->values('link_domain'));
        $this->assertSame(['softfail'], $m->values('auth_spf'));
        $this->assertSame(['none'], $m->values('auth_dkim'));
        $this->assertSame(['fail'], $m->values('auth_dmarc'));
        $this->assertSame(['google'], $m->values('mx_provider'));
        $this->assertSame(['12'], $m->values('domain_age'));
        $this->assertSame(['x@evil.ru'], $m->values('return_path'));
        $this->assertSame(['external'], $m->values('from_scope'));
        $this->assertSame(['nie'], $m->values('from_freemail'));
        $this->assertSame(['list'], $m->values('message_type'));
        $this->assertSame(['203.0.113.7'], $m->values('sender_ip'));
        $this->assertSame(['1'], $m->values('size_kb'));
        $this->assertSame(['1'], $m->values('attachment_count'));
        $this->assertSame(['application/octet-stream'], $m->values('attachment_type'));
        $this->assertSame(['internal'], ComplexRuleMessage::fromRaw("From: a@sub.firma.pl\r\n\r\nx", null, 'jan@firma.pl')->values('from_scope'));
    }

    public function testAndOrNegate()
    {
        // Subject contains "faktura" AND body does not contain "umowa".
        $this->assertTrue($this->eval(['op' => 'and', 'items' => [
            ['field' => 'subject', 'match' => 'contains', 'value' => 'Faktura'],
            ['field' => 'body', 'match' => 'contains', 'value' => 'umowa', 'negate' => true],
        ]]));
        $this->assertFalse($this->eval(['op' => 'and', 'items' => [
            ['field' => 'subject', 'match' => 'contains', 'value' => 'faktura'],
            ['field' => 'body', 'match' => 'contains', 'value' => 'zapłatę', 'negate' => true],
        ]]));
        // Whitespace in the body is folded.
        $this->assertTrue($this->eval(['field' => 'body', 'match' => 'contains', 'value' => 'o zapłatę']));
        $this->assertTrue($this->eval(['op' => 'or', 'items' => [
            ['field' => 'from_domain', 'match' => 'equals', 'value' => 'firma.pl'],
            ['op' => 'and', 'items' => [
                ['field' => 'from_domain', 'match' => 'wildcard', 'value' => '*.ru'],
                ['field' => 'attachment', 'match' => 'regex', 'value' => '\.exe$'],
            ]],
        ]]));
        $this->assertTrue($this->eval(['field' => 'to', 'match' => 'equals', 'value' => 'anna@firma.pl']));
        $this->assertTrue($this->eval(['field' => 'to', 'match' => 'ends', 'value' => '@inna.pl', 'negate' => true]));
        $this->assertTrue($this->eval(['field' => 'reply_to', 'match' => 'empty']));
        $this->assertTrue($this->eval(['field' => 'header', 'header' => 'List-Id', 'match' => 'empty']));
        // NOT (from *.ru OR has attachment) is false; NOT on a non-matching group is true.
        $this->assertFalse($this->eval(['op' => 'or', 'negate' => true, 'items' => [
            ['field' => 'from_domain', 'match' => 'ends', 'value' => '.ru'],
            ['field' => 'attachment_count', 'match' => 'gt', 'value' => '0'],
        ]]));
        $this->assertTrue($this->eval(['op' => 'and', 'items' => [
            ['field' => 'subject', 'match' => 'contains', 'value' => 'faktura'],
            ['op' => 'and', 'negate' => true, 'items' => [['field' => 'from_scope', 'match' => 'equals', 'value' => 'internal']]],
        ]]));
        $this->assertTrue($this->eval(['field' => 'subject', 'match' => 'wildcard', 'value' => 'pilna*nr ??/2026']));
    }

    public function testIntelFields()
    {
        $this->assertTrue($this->eval(['field' => 'domain_age', 'match' => 'lt', 'value' => '30']));
        $this->assertFalse($this->eval(['field' => 'domain_age', 'match' => 'gt', 'value' => '30']));
        $this->assertTrue($this->eval(['op' => 'and', 'items' => [
            ['field' => 'mx_provider', 'match' => 'equals', 'value' => 'google'],
            ['field' => 'auth_dmarc', 'match' => 'equals', 'value' => 'fail'],
        ]]));
        $this->assertSame('google', SenderIntelService::classifyMx(['alt1.aspmx.l.google.com']));
        $this->assertSame('microsoft', SenderIntelService::classifyMx(['firma-pl.mail.protection.outlook.com']));
        $this->assertSame('homepl', SenderIntelService::classifyMx(['mx.home.pl']));
        $this->assertSame('other', SenderIntelService::classifyMx(['mx.firma.pl']));
        $this->assertSame('none', SenderIntelService::classifyMx([]));
        $this->assertSame(strtotime('2024-03-05 10:00:00'), SenderIntelService::parseWhoisCreated("DOMAIN NAME: x.pl\ncreated: 2024.03.05 10:00:00\n"));
        $this->assertSame(strtotime('2019-01-02T03:04:05Z'), SenderIntelService::parseWhoisCreated("   Creation Date: 2019-01-02T03:04:05Z\n"));
    }

    public function testValidation()
    {
        $this->assertNull(ComplexRuleEngine::normalize(['op' => 'and', 'items' => []], $e));
        $this->assertNotEmpty($e);
        $this->assertNull(ComplexRuleEngine::normalize(['field' => 'subject', 'match' => 'contains', 'value' => ''], $e));
        $this->assertNull(ComplexRuleEngine::normalize(['field' => 'subject', 'match' => 'regex', 'value' => '(a'], $e));
        $this->assertNull(ComplexRuleEngine::normalize(['field' => 'subject', 'match' => 'lt', 'value' => '3'], $e));
        $this->assertNull(ComplexRuleEngine::normalize(['field' => 'domain_age', 'match' => 'contains', 'value' => '3'], $e));
        $this->assertNull(ComplexRuleEngine::normalize(['field' => 'domain_age', 'match' => 'lt', 'value' => 'abc'], $e));
        $this->assertNull(ComplexRuleEngine::normalize(['field' => 'header', 'match' => 'empty'], $e));
        $this->assertNull(ComplexRuleEngine::normalize(['field' => 'nope', 'match' => 'contains', 'value' => 'x'], $e));
        $deep = ['field' => 'subject', 'match' => 'contains', 'value' => 'x'];
        for ($i = 0; $i < 5; $i++) {
            $deep = ['op' => 'and', 'items' => [$deep]];
        }
        $this->assertNull(ComplexRuleEngine::normalize($deep, $e));

        $n = ComplexRuleEngine::normalize(['field' => 'subject', 'match' => 'contains', 'value' => '  Pilna   FAKTURA ', 'junk' => 1]);
        $this->assertSame(['op' => 'and', 'items' => [['field' => 'subject', 'match' => 'contains', 'value' => 'pilna faktura', 'negate' => false]], 'negate' => false], $n);
        $this->assertSame('Temat zawiera „pilna faktura”', ComplexRuleEngine::describe($n));
    }

    public function testReDoSRegexIsRejected()
    {
        $this->assertNull(ComplexRuleEngine::normalize(['field' => 'subject', 'match' => 'regex', 'value' => '(a+)+$'], $e));
    }
}
