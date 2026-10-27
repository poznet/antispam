<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\ImapFlags;
use AntispamBundle\Services\ImapTlsProbe;
use PHPUnit\Framework\TestCase;

class ImapFlagsTest extends TestCase
{
    public function testBuild()
    {
        $this->assertSame('/imap/ssl', ImapFlags::build(ImapFlags::defaultOptions()));
        $this->assertSame('/imap/ssl/novalidate-cert', ImapFlags::build(['encryption' => 'ssl', 'validate_cert' => '0']));
        $this->assertSame('/imap/tls', ImapFlags::build(['encryption' => 'starttls', 'validate_cert' => '1']));
        $this->assertSame('/imap/novalidate-cert', ImapFlags::build(['encryption' => 'auto']));
        $this->assertSame('/imap/notls', ImapFlags::build(['encryption' => 'none', 'validate_cert' => '0']), 'no cert flag without TLS');
        $this->assertSame('/imap/ssl/secure/norsh/debug', ImapFlags::build(['encryption' => 'ssl', 'validate_cert' => 1, 'secure' => 1, 'norsh' => 1, 'debug' => 1]));
        $this->assertSame('/imap/ssl', ImapFlags::build(['encryption' => 'bogus', 'validate_cert' => 1]));
    }

    public function testParseRoundTrip()
    {
        foreach (['/imap/ssl', '/imap/ssl/novalidate-cert', '/imap/tls', '/imap', '/imap/notls', '/imap/tls/novalidate-cert/secure/norsh'] as $flags) {
            $options = ImapFlags::parse($flags);
            $this->assertFalse($options['custom'], $flags);
            $this->assertSame($flags, ImapFlags::build($options), $flags);
        }
    }

    public function testParseLegacyAndCustom()
    {
        $o = ImapFlags::parse('/novalidate-cert/notls');
        $this->assertSame('none', $o['encryption']);
        $this->assertFalse($o['custom']);

        $this->assertSame('ssl', ImapFlags::parse('/IMAP/SSL/validate-cert')['encryption']);
        $this->assertEquals(ImapFlags::defaultOptions(), ImapFlags::parse(null));
        $this->assertTrue(ImapFlags::parse('/imap/ssl/readonly')['custom']);
        $this->assertTrue(ImapFlags::parse('/imap/ssl/notls')['custom']);
    }

    public function testFromFormData()
    {
        $this->assertSame('/imap/tls/novalidate-cert', ImapFlags::fromFormData([
            'imap_tls' => ['encryption' => 'starttls', 'validate_cert' => '0'],
            'imap_flags' => '/ignored',
        ]));
        $this->assertSame('/imap/ssl/readonly', ImapFlags::fromFormData([
            'imap_tls' => ['encryption' => 'starttls'],
            'imap_flags_custom' => '1',
            'imap_flags' => ' /imap/ssl/readonly} ',
        ]));
        $this->assertSame('/imap/ssl', ImapFlags::fromFormData(['imap_flags_custom' => '1', 'imap_flags' => '']));
        $this->assertSame('/imap/ssl', ImapFlags::fromFormData(['imap_flags' => 'imap/ssl']), 'old form without imap_tls');
    }

    public function testHostnameMatches()
    {
        $this->assertTrue(ImapTlsProbe::hostnameMatches('mail.example.com', ['mail.example.com']));
        $this->assertTrue(ImapTlsProbe::hostnameMatches('Mail.Example.com', ['*.example.com']));
        $this->assertFalse(ImapTlsProbe::hostnameMatches('a.b.example.com', ['*.example.com']));
        $this->assertFalse(ImapTlsProbe::hostnameMatches('example.com', ['*.example.com']));
        $this->assertFalse(ImapTlsProbe::hostnameMatches('mail.domena.pl', ['s1.hosting.pl']));
    }

    public function testDescribeSelfSignedCertificate()
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $csr = openssl_csr_new(['commonName' => 's1.hosting.pl'], $key);
        $cert = openssl_csr_sign($csr, null, $key, 30);

        $c = ImapTlsProbe::describeCertificate($cert, 'mail.domena.pl');
        $this->assertSame('s1.hosting.pl', $c['subject_cn']);
        $this->assertSame(['s1.hosting.pl'], $c['names']);
        $this->assertTrue($c['self_signed']);
        $this->assertFalse($c['hostname_match']);
        $this->assertFalse($c['expired']);
        $this->assertGreaterThanOrEqual(29, $c['days_left']);
        $this->assertSame(64, strlen($c['fingerprint']));
    }
}
