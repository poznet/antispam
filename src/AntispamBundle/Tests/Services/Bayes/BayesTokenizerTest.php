<?php

namespace AntispamBundle\Tests\Services\Bayes;

use AntispamBundle\Services\Bayes\BayesTokenizer;
use PHPUnit\Framework\TestCase;

class BayesTokenizerTest extends TestCase
{
    public function testTokensFromAllSources()
    {
        $tokens = BayesTokenizer::tokenize([
            'subject' => 'Pilna FAKTURA do zapłaty',
            'from' => 'Biuro@Firma.PL',
            'reply_to' => 'x@evil.example',
            'message_id' => '<abc.123@mail.firma.pl>',
            'x_mailer' => 'PHPMailer 6.8.1',
            'content_type' => 'multipart/alternative; boundary="b"',
            'text' => "Zażółć gęślą jaźń. Kliknij https://login.bank-pl.example.com/x?y=1 teraz\n12345 ok to",
        ]);

        foreach (['subject:pilna', 'subject:faktura', 'subject:zapłaty', 'from:firma.pl', 'replyto:evil.example', 'replyto:differs',
                     'msgid:mail.firma.pl', 'xmailer:phpmailer #.#.#', 'ctype:multipart/alternative',
                     'url:login.bank-pl.example.com', 'url:example.com', 'zażółć', 'gęślą', 'jaźń', 'kliknij', 'teraz'] as $t) {
            $this->assertContains($t, $tokens, $t);
        }
        // short words, pure numbers and URL fragments are not tokens
        foreach (['ok', 'to', '12345', 'https', 'login', 'subject:do'] as $t) {
            $this->assertNotContains($t, $tokens, $t);
        }
        $this->assertSame(count($tokens), count(array_unique($tokens)));
    }

    public function testLongWordsSkipAndHtmlFallback()
    {
        $tokens = BayesTokenizer::tokenize(['html' => '<p>Konstantynopolitańczykowianeczka</p><style>.x{}</style><b>Promocja</b>']);
        $this->assertContains('skip:k:30', $tokens);
        $this->assertContains('promocja', $tokens);
        $this->assertContains('from:none', $tokens);
        $this->assertContains('msgid:none', $tokens);
        $this->assertContains('xmailer:none', $tokens);
        $this->assertNotContains('replyto:differs', $tokens);
    }

    public function testTokenCapAndInvalidUtf8()
    {
        $text = implode(' ', array_map(fn($i) => 'slowo' . base_convert((string)$i, 10, 26), range(1, 3000)));
        $this->assertCount(BayesTokenizer::MAX_TOKENS, BayesTokenizer::tokenize(['text' => $text]));
        $this->assertNotEmpty(BayesTokenizer::tokenize(['text' => "zly \xC3\x28 bajt tekst"]));
    }

    public function testHashIsCompactAndRoundTrips()
    {
        $hex = BayesTokenizer::hash('promocja');
        $this->assertSame(substr(sha1('promocja'), 0, 16), $hex);
        $this->assertSame($hex, BayesTokenizer::intToHex(BayesTokenizer::hexToInt($hex)));
        $this->assertSame('ffffffffffffffff', BayesTokenizer::intToHex(BayesTokenizer::hexToInt('ffffffffffffffff')));
        $this->assertSame(-1, BayesTokenizer::hexToInt('ffffffffffffffff'));
        $this->assertSame(['a', 'b'], array_map(fn($h) => $h === BayesTokenizer::hash('x') ? 'a' : 'b', BayesTokenizer::hashes(['x', 'y', 'x'])));
    }

    public function testFieldsFromRaw()
    {
        $raw = "From: =?UTF-8?B?SmFu?= <jan@firma.pl>\r\nReply-To: <r@inna.pl>\r\nSubject: =?UTF-8?Q?Zap=C5=82ata?=\r\nMessage-ID: <1@firma.pl>\r\nX-Mailer: Outlook 16\r\n"
            . "Content-Type: text/plain; charset=utf-8\r\n\r\nTreść wiadomości\r\n";
        $f = BayesTokenizer::fieldsFromRaw($raw);
        $this->assertSame('Zapłata', $f['subject']);
        $this->assertSame('jan@firma.pl', $f['from']);
        $this->assertSame('r@inna.pl', $f['reply_to']);
        $this->assertSame('<1@firma.pl>', $f['message_id']);
        $this->assertSame('Outlook 16', $f['x_mailer']);
        $this->assertStringContainsString('Treść', $f['text']);
    }
}
