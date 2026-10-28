<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\MailClientPluginBuilder;
use PHPUnit\Framework\TestCase;

class MailClientPluginBuilderTest extends TestCase
{
    public function testOutlookManifestIsValidXmlWithServerUrls()
    {
        $xml = (new MailClientPluginBuilder())->outlookManifest('https://antispam.example.pl:8443/sub/');
        $this->assertStringNotContainsString('{{', $xml);

        $doc = new \DOMDocument();
        $this->assertTrue($doc->loadXML($xml), 'manifest must be well-formed XML');
        $xp = new \DOMXPath($doc);
        $xp->registerNamespace('o', 'http://schemas.microsoft.com/office/appforoffice/1.1');
        $xp->registerNamespace('bt', 'http://schemas.microsoft.com/office/officeappbasictypes/1.0');

        $this->assertSame('https://antispam.example.pl:8443', $xp->evaluate('string(//o:AppDomains/o:AppDomain)'));
        $this->assertSame(
            'https://antispam.example.pl:8443/sub/plugin/outlook/taskpane.html',
            $xp->evaluate('string(//o:FormSettings//o:SourceLocation/@DefaultValue)')
        );
        $this->assertSame('ReadItem', $xp->evaluate('string(//o:Permissions)'));

        // Every URL in the manifest points to an asset the app actually serves.
        $b = new MailClientPluginBuilder();
        foreach ($xp->query('//@DefaultValue') as $attr) {
            $v = $attr->value;
            if (str_starts_with($v, 'https://antispam.example.pl:8443/sub/plugin/outlook/')) {
                $file = substr($v, strlen('https://antispam.example.pl:8443/sub/plugin/outlook/'));
                $this->assertNotNull($b->outlookAsset($file), "manifest references missing asset $file");
            }
        }
    }

    public function testOutlookManifestEscapesUrl()
    {
        $xml = (new MailClientPluginBuilder())->outlookManifest('https://a.example.pl/x?a=1&b=2');
        $doc = new \DOMDocument();
        $this->assertTrue($doc->loadXML($xml));
    }

    public function testOutlookAssetWhitelist()
    {
        $b = new MailClientPluginBuilder();
        $this->assertSame('text/html; charset=UTF-8', $b->outlookAsset('taskpane.html')['type']);
        $this->assertSame('image/png', $b->outlookAsset('icons/icon-80.png')['type']);
        $this->assertNull($b->outlookAsset('manifest.xml'));
        $this->assertNull($b->outlookAsset('../outlook/taskpane.html'));
        $this->assertNull($b->outlookAsset('icons/icon-999.png'));
    }

    public function testOutlookRequiresHttps()
    {
        $this->assertTrue(MailClientPluginBuilder::isOutlookCompatible('https://antispam.example.pl'));
        $this->assertTrue(MailClientPluginBuilder::isOutlookCompatible('http://localhost:8000'));
        $this->assertFalse(MailClientPluginBuilder::isOutlookCompatible('http://antispam.example.pl'));
        $this->assertFalse(MailClientPluginBuilder::isOutlookCompatible(''));
    }

    public function testAppleMailSourceZipHasServerBakedIn()
    {
        if (!class_exists(\ZipArchive::class)) {
            $this->markTestSkipped('zip extension missing');
        }
        $path = (new MailClientPluginBuilder())->appleMailSourceZip('https://antispam.example.pl/');
        try {
            $zip = new \ZipArchive();
            $this->assertTrue($zip->open($path) === true);
            $config = $zip->getFromName('antispam-apple-mail/Shared/ServerConfig.swift');
            $this->assertStringContainsString('"https://antispam.example.pl"', $config);
            $this->assertStringNotContainsString('static let bundledServer = "__ANTISPAM_SERVER__"', $config);
            $this->assertNotFalse($zip->getFromName('antispam-apple-mail/README.md'));
            $this->assertNotFalse($zip->getFromName('antispam-apple-mail/project.yml'));
            $this->assertNotFalse($zip->getFromName('antispam-apple-mail/MailExtension/MessageActionHandler.swift'));
            $zip->close();
        } finally {
            @unlink($path);
        }
    }
}
