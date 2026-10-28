<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\PhishingReport;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\RawMessageParser;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;

class PhishingReportServiceTest extends TestCase
{
    private const RAW = "Authentication-Results: mx.example.com; spf=softfail smtp.mailfrom=bank-pl.top; dkim=pass header.d=mailer.top; dmarc=fail header.from=bank.pl\r\n"
        . "DKIM-Signature: v=1; a=rsa-sha256; d=mailer.top; s=x; b=abc\r\n"
        . "Received: from mail.bank-pl.top ([203.0.113.9]) by mx.example.com\r\n"
        . "From: \"bok@bank.pl\" <alert@bank.pl>\r\n"
        . "Reply-To: <zwrot@evil.top>\r\n"
        . "Return-Path: <bounce@bank-pl.top>\r\n"
        . "Subject: =?UTF-8?B?WmFibG9rb3dhbmUga29udG8=?=\r\n"
        . "Message-ID: <abc@bank-pl.top>\r\n"
        . "MIME-Version: 1.0\r\n"
        . "Content-Type: multipart/mixed; boundary=\"b1\"\r\n"
        . "\r\n"
        . "--b1\r\n"
        . "Content-Type: text/html; charset=UTF-8\r\n"
        . "\r\n"
        . "<p>Zaloguj: <a href=\"https://login.evil.top/pl\">https://www.bank.pl/logowanie</a>"
        . " <a href=\"http://198.51.100.7/x\">tutaj</a> <a href=\"https://www.bank.pl/pomoc\">bank.pl</a></p>\r\n"
        . "--b1\r\n"
        . "Content-Type: application/octet-stream; name=\"faktura.pdf.exe\"\r\n"
        . "Content-Disposition: attachment; filename=\"faktura.pdf.exe\"\r\n"
        . "Content-Transfer-Encoding: base64\r\n"
        . "\r\n"
        . "TVqQAAMAAAAEAAAA\r\n"
        . "--b1--\r\n";

    private function report()
    {
        $msg = new RawMessageParser(self::RAW);
        return (new PhishingReport())->setRaw(self::RAW)->setAccountEmail('jan@example.com')
            ->setSender($msg->getFromAddress())->setSenderName($msg->getFromName())
            ->setReplyTo($msg->getAddress('reply-to'))->setReturnPath($msg->getAddress('return-path'))
            ->setSubject($msg->getSubject());
    }

    public function testParsesStoredFields()
    {
        $r = $this->report();
        $this->assertSame('alert@bank.pl', $r->getSender());
        $this->assertSame('zwrot@evil.top', $r->getReplyTo());
        $this->assertSame('bounce@bank-pl.top', $r->getReturnPath());
        $this->assertSame('Zablokowane konto', $r->getSubject());
        $this->assertSame(hash('sha256', self::RAW), $r->getSha256());
    }

    public function testAnalyze()
    {
        $a = (new PhishingReportService($this->createMock(EntityManagerInterface::class)))->analyze($this->report());

        $this->assertSame(['spf' => 'softfail', 'dkim' => 'pass', 'dmarc' => 'fail'], $a['auth']);
        $this->assertSame(['mailer.top'], $a['dkim_domains']);

        $byHref = array_column($a['links'], null, 'href');
        $this->assertTrue($byHref['https://login.evil.top/pl']['mismatch']);
        $this->assertFalse($byHref['https://www.bank.pl/pomoc']['mismatch']); // www.bank.pl is a subdomain of the shown bank.pl
        $this->assertTrue($byHref['http://198.51.100.7/x']['ip']);

        $this->assertCount(1, $a['attachments']);
        $this->assertTrue($a['attachments'][0]['risky']);
        $this->assertSame(hash('sha256', base64_decode('TVqQAAMAAAAEAAAA')), $a['attachments'][0]['sha256']);

        $flags = implode("\n", $a['flags']);
        foreach (['SPF: softfail', 'DMARC: fail', 'DKIM innej domeny', 'zwrot@evil.top', 'Return-Path', 'udaje inny adres', 'tekst', 'adresu IP', 'faktura.pdf.exe'] as $needle) {
            $this->assertStringContainsString($needle, $flags);
        }
        $this->assertSame('Subject', $a['headers'][6]['name']);
        $this->assertSame('Zablokowane konto', $a['headers'][6]['value']);
    }

    public function testFreemail()
    {
        $this->assertTrue(PhishingReportService::isFreemail('WP.pl'));
        $this->assertFalse(PhishingReportService::isFreemail('bank-pl.top'));
        $this->assertSame('evil.top', PhishingReportService::domainOf('a@Evil.TOP'));
    }
}
