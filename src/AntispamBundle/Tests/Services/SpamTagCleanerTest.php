<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\SpamFolderService;
use AntispamBundle\Services\SpamTagCleaner;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Spam marks removed on release (panel and agent the same) + the domain patterns of "Przywróć z domeny". */
class SpamTagCleanerTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!defined('ANTISPAM_AGENT_LIBRARY')) {
            define('ANTISPAM_AGENT_LIBRARY', true);
        }
        if (class_exists(\SQLite3::class)) {
            require_once __DIR__ . '/../../Resources/agent/antispam-agent.php';
        }
    }

    public static function subjects(): iterable
    {
        yield ['[SPAM] Faktura', 'Faktura'];
        yield ['***SPAM*** Faktura', 'Faktura'];
        yield ['*****SPAM***** Faktura', 'Faktura'];
        yield ['{Spam?} Faktura', 'Faktura'];
        yield ['[Possible Spam] Faktura', 'Faktura'];
        yield ['[Potencjalny SPAM] Faktura', 'Faktura'];
        yield ['SPAM: Faktura', 'Faktura'];
        yield ['[SPAM] [SPAM] Faktura', 'Faktura'];
        yield ['(JUNK) Faktura', 'Faktura'];
        yield ['Faktura [SPAM]', 'Faktura [SPAM]'];
        yield ['Spamowanie to problem', 'Spamowanie to problem'];
        yield ['Re: [SPAM] x', 'Re: [SPAM] x'];
        yield ['[SPAM]', '[SPAM]'];
        yield ['', ''];
    }

    #[DataProvider('subjects')]
    public function testCleanSubject(string $in, string $out)
    {
        $this->assertSame($out, SpamTagCleaner::cleanSubject($in));
        if (function_exists('agentCleanSubject')) {
            $this->assertSame($out, \agentCleanSubject($in), 'agent parity');
        }
    }

    public function testCleanMessageOnlyTouchesHeaders()
    {
        $raw = "From: a@b.pl\r\nSubject: [SPAM] Hej\r\nX-Spam-Flag: YES\r\n\r\nSubject: [SPAM] w treści\r\n";
        $clean = SpamTagCleaner::clean($raw);
        $this->assertSame("From: a@b.pl\r\nSubject: Hej\r\nX-Spam-Flag: NO\r\n\r\nSubject: [SPAM] w treści\r\n", $clean);
        $this->assertNull(SpamTagCleaner::clean("From: a@b.pl\nSubject: Hej\n\nx"), 'nothing to change');
        if (function_exists('agentCleanSpamTags')) {
            $this->assertSame($clean, \agentCleanSpamTags($raw));
        }
    }

    public function testDomainPatterns()
    {
        $this->assertSame('firma.pl', SpamFolderService::domainPattern(' Firma.PL '));
        $this->assertSame('*.firma.pl', SpamFolderService::domainPattern('*.firma.pl'));
        $this->assertSame('firma.pl', SpamFolderService::domainPattern('@firma.pl'));
        $this->assertSame('firma.pl', SpamFolderService::domainPattern('*@firma.pl'));
        foreach (['', '*', '*.pl', 'pl', 'a@b.pl', 'firma', 'fir ma.pl', '*.*.pl', '../x.pl'] as $bad) {
            $this->assertNull(SpamFolderService::domainPattern($bad), $bad);
        }
        $this->assertTrue(SpamFolderService::senderInDomain('a@firma.pl', 'firma.pl'));
        $this->assertFalse(SpamFolderService::senderInDomain('a@mail.firma.pl', 'firma.pl'));
        $this->assertTrue(SpamFolderService::senderInDomain('a@mail.firma.pl', '*.firma.pl'));
        $this->assertTrue(SpamFolderService::senderInDomain('a@firma.pl', '*.firma.pl'));
        $this->assertFalse(SpamFolderService::senderInDomain('a@nie-firma.pl', '*.firma.pl'));
        $this->assertFalse(SpamFolderService::senderInDomain('a@firma.pl.evil.ru', '*.firma.pl'));
    }
}
