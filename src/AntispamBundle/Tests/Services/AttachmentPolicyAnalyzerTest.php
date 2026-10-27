<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use PHPUnit\Framework\TestCase;

class AttachmentPolicyAnalyzerTest extends TestCase
{
    private function analyze(array $attachments, array $config = [])
    {
        return (new AttachmentPolicyAnalyzer())->analyze($attachments, $config);
    }

    private function rules(array $result)
    {
        return array_map(function ($r) { return strtok($r['rule'], ':'); }, $result['reasons']);
    }

    private static function pe()
    {
        return 'MZ' . str_repeat("\0", 58) . pack('V', 64) . "PE\0\0" . str_repeat("\0", 32);
    }

    private static function zip(array $entries)
    {
        $out = '';
        foreach ($entries as $name => $flags) {
            $out .= "PK\x03\x04" . pack('vvvvvVVVvv', 20, $flags, 0, 0, 0, 0, 3, 3, strlen($name), 0) . $name . 'abc';
        }
        return $out . "PK\x05\x06" . str_repeat("\0", 18);
    }

    public function testBlockedAndDoubleExtension()
    {
        $r = $this->analyze([['filename' => 'Faktura.PDF.exe', 'data' => 'x']]);
        $this->assertSame(['attachment_blocked', 'attachment_double_extension'], $this->rules($r));
        $this->assertSame(15 + 8, $r['score']);
    }

    public function testTrailingDotsAndPaddingAreSeenThrough()
    {
        $this->assertSame(['attachment_blocked'], $this->rules($this->analyze([['filename' => 'setup.exe. ', 'data' => 'x']])));
        $this->assertContains('attachment_double_extension', $this->rules($this->analyze([['filename' => 'scan.pdf          .scr', 'data' => 'x']])));
    }

    public function testRfc2231AndBidiNames()
    {
        $this->assertSame(['attachment_blocked'], $this->rules($this->analyze([['filename' => "utf-8''raport%20Q3.js", 'data' => 'x']])));
        $this->assertContains('attachment_bidi_filename', $this->rules($this->analyze([['filename' => "faktura\u{202E}fdp.exe", 'data' => 'x']])));
    }

    public function testDisguisedExecutable()
    {
        $r = $this->analyze([['filename' => 'umowa.pdf', 'data' => self::pe()]]);
        $this->assertSame(['attachment_disguised_executable'], $this->rules($r));
        // "MZ" text without a PE header is not an executable
        $this->assertSame(0, $this->analyze([['filename' => 'notes.txt', 'data' => 'MZ notes ' . str_repeat('x', 100)]])['score']);
    }

    public function testArchiveContents()
    {
        $this->assertSame(['attachment_archive_blocked'], $this->rules($this->analyze([['filename' => 'docs.zip', 'data' => self::zip(['readme.txt' => 0, 'invoice.pdf.js' => 0])]])));
        $this->assertSame(['attachment_encrypted_archive'], $this->rules($this->analyze([['filename' => 'secret.zip', 'data' => self::zip(['a.pdf' => 1])]])));
        $this->assertSame(0, $this->analyze([['filename' => 'photos.zip', 'data' => self::zip(['a.jpg' => 0])]])['score']);
    }

    public function testOfficeMacros()
    {
        $docm = self::zip(['[Content_Types].xml' => 0, 'word/document.xml' => 0, 'word/vbaProject.bin' => 0]);
        $this->assertSame(['attachment_office_macro'], $this->rules($this->analyze([['filename' => 'oferta.docx', 'data' => $docm]])));

        $docx = self::zip(['[Content_Types].xml' => 0, 'word/document.xml' => 0]);
        $this->assertSame(0, $this->analyze([['filename' => 'oferta.docx', 'data' => $docx]])['score']);

        $ole = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" . str_repeat("\0", 100) . implode("\0", str_split('_VBA_PROJECT')) . "\0";
        $this->assertSame(['attachment_office_macro'], $this->rules($this->analyze([['filename' => 'stary.doc', 'data' => $ole]])));
    }

    public function testPdfJavascript()
    {
        $this->assertSame(['attachment_pdf_active'], $this->rules($this->analyze([['filename' => 'a.pdf', 'data' => "%PDF-1.7\n1 0 obj << /S /JavaScript /JS (app.alert(1)) >>"]])));
        $this->assertSame(0, $this->analyze([['filename' => 'a.pdf', 'data' => "%PDF-1.7\n1 0 obj << /Type /Page >>"]])['score']);
    }

    public function testCustomBlockListAndZeroScores()
    {
        $r = $this->analyze([['filename' => 'a.exe', 'data' => 'x'], ['filename' => 'b.docm', 'data' => 'x']], ['blocked_extensions' => 'docm']);
        $this->assertSame(['attachment_blocked'], $this->rules($r));
        $this->assertSame('b.docm', $r['reasons'][0]['filename']);
        $this->assertSame(0, $this->analyze([['filename' => 'a.exe', 'data' => 'x']], ['blocked_score' => 0, 'double_ext_score' => 0])['score']);
    }
}
