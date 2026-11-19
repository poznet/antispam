<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\ComplexRuleEngine;
use AntispamBundle\Services\ComplexRuleMessage;
use AntispamBundle\Services\DomainHelper;
use AntispamBundle\Services\SenderIntelService;
use PHPUnit\Framework\TestCase;

/**
 * Complex rules: the Maildir agent's copy (complex*() in antispam-agent.php)
 * must read the same field values and give the same verdicts as
 * ComplexRuleEngine / ComplexRuleMessage.
 */
class ComplexRuleAgentParityTest extends TestCase
{
    private const RAW = "Return-Path: <bounce@evil.ru>\r\n"
        . "Received: from relay.evil.ru (relay.evil.ru [203.0.113.7]) by mx.firma.pl\r\n"
        . "Authentication-Results: mx.firma.pl; spf=softfail smtp.mailfrom=evil.ru; dkim=fail; dkim=pass; dmarc=fail\r\n"
        . "From: =?UTF-8?Q?Dzia=C5=82_Faktur?= <Faktury@Mail.Evil.RU>\r\n"
        . "To: Jan <jan@firma.pl>,\r\n anna@firma.pl\r\n"
        . "Cc: biuro@firma.pl\r\n"
        . "Reply-To: <pay@other.top>\r\n"
        . "Subject: =?UTF-8?Q?Pilna_FAKTURA_nr_12/2026?=\r\n"
        . "X-Mailer: PHPMailer 6.1\r\n"
        . "Auto-Submitted: auto-generated\r\n"
        . "MIME-Version: 1.0\r\n"
        . "Content-Type: multipart/mixed; boundary=\"b1\"\r\n"
        . "\r\n"
        . "--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        . "Prosimy o   zapłatę: https://pay.bad-link.top/x\r\n"
        . "--b1\r\nContent-Type: application/pdf; name=\"faktura.pdf\"\r\nContent-Disposition: attachment; filename=\"faktura.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n"
        . "--b1--\r\n";

    private const FIELDS = ['from', 'from_domain', 'from_name', 'to', 'reply_to', 'return_path', 'from_scope', 'from_freemail',
        'subject', 'body', 'attachment', 'attachment_type', 'attachment_count', 'size_kb', 'message_type', 'sender_ip',
        'link_domain', 'auth_spf', 'auth_dkim', 'auth_dmarc'];

    private static string $file;

    public static function setUpBeforeClass(): void
    {
        if (!defined('ANTISPAM_AGENT_LIBRARY')) {
            define('ANTISPAM_AGENT_LIBRARY', true);
        }
        require_once __DIR__ . '/../../Resources/agent/antispam-agent.php';
        self::$file = tempnam(sys_get_temp_dir(), 'crp');
        file_put_contents(self::$file, self::RAW);
    }

    public static function tearDownAfterClass(): void
    {
        @unlink(self::$file);
    }

    private function agentValues(): callable
    {
        $headers = \readHeaderBlock(self::$file);
        $parts = null;
        return \complexFieldProvider(self::$file, $headers, function () use (&$parts) { return $parts ??= \parseMessageParts(self::$file); },
            ['settings' => ['mailbox_email' => 'jan@firma.pl', 'complex_lookups' => '0']], null);
    }

    public function testFieldValues()
    {
        $web = ComplexRuleMessage::fromRaw(self::RAW, null, 'jan@firma.pl');
        $agent = $this->agentValues();
        foreach (self::FIELDS as $f) {
            $w = array_map([ComplexRuleEngine::class, 'fold'], $web->values($f));
            $a = array_map('complexFold', $agent($f, null));
            $this->assertSame($w, $a, 'field ' . $f);
        }
        $this->assertSame(array_map([ComplexRuleEngine::class, 'fold'], $web->values('header', 'X-Mailer')), array_map('complexFold', $agent('header', 'x-mailer')));
    }

    public static function trees(): array
    {
        return [
            [['op' => 'and', 'items' => [['field' => 'subject', 'match' => 'contains', 'value' => 'faktura'], ['field' => 'body', 'match' => 'contains', 'value' => 'umowa', 'negate' => true]]]],
            [['op' => 'or', 'negate' => true, 'items' => [['field' => 'from_domain', 'match' => 'wildcard', 'value' => '*.ru'], ['field' => 'attachment', 'match' => 'regex', 'value' => '\.exe$']]]],
            [['field' => 'subject', 'match' => 'wildcard', 'value' => 'pilna*nr ??/2026']],
            [['field' => 'to', 'match' => 'ends', 'value' => '@firma.pl']],
            [['field' => 'auth_dkim', 'match' => 'equals', 'value' => 'pass']],
            [['field' => 'attachment_count', 'match' => 'gt', 'value' => '0']],
            [['field' => 'size_kb', 'match' => 'lt', 'value' => '2']],
            [['field' => 'message_type', 'match' => 'equals', 'value' => 'autoreply']],
            [['field' => 'from_scope', 'match' => 'equals', 'value' => 'internal']],
            [['field' => 'reply_to', 'match' => 'starts', 'value' => 'pay@']],
            [['field' => 'header', 'header' => 'List-Id', 'match' => 'empty']],
            [['field' => 'mx_provider', 'match' => 'equals', 'value' => 'google', 'negate' => true]],
            [['field' => 'body', 'match' => 'contains', 'value' => 'o zapłatę']],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('trees')]
    public function testVerdicts(array $tree)
    {
        $norm = ComplexRuleEngine::normalize($tree, $errors);
        $this->assertNotNull($norm, implode(' ', $errors));
        $web = ComplexRuleEngine::evaluate($norm, ComplexRuleMessage::fromRaw(self::RAW, null, 'jan@firma.pl')->provider());
        $this->assertSame($web, \complexEvaluate($norm, $this->agentValues()));
    }

    public function testListsAndHelpers()
    {
        $this->assertSame(DomainHelper::freemailList(), \COMPLEX_FREEMAIL);
        $ref = new \ReflectionClassConstant(SenderIntelService::class, 'MX_PROVIDERS');
        $this->assertSame($ref->getValue(), \COMPLEX_MX_PROVIDERS);
        foreach ([['aspmx.l.google.com'], ['x.mail.protection.outlook.com'], ['mx.firma.pl'], []] as $hosts) {
            $this->assertSame(SenderIntelService::classifyMx($hosts), \complexClassifyMx($hosts));
        }
        foreach (["created: 2024.03.05 10:00:00\n", "Creation Date: 2019-01-02T03:04:05Z\n", "nothing\n"] as $text) {
            $this->assertSame(SenderIntelService::parseWhoisCreated($text), \complexParseWhoisCreated($text));
        }
    }

    public function testImportAndScore()
    {
        $db = new \SQLite3(':memory:');
        $db->exec('CREATE TABLE complex_rules (id INTEGER PRIMARY KEY, email TEXT, name TEXT, action TEXT, score INTEGER DEFAULT 0, conditions TEXT)');
        foreach (['whitelist', 'email_whitelist', 'blacklist', 'email_blacklist', 'dnsbl_providers', 'settings', 'bayes_tokens'] as $t) {
            $db->exec('CREATE TABLE ' . $t . ' (id INTEGER PRIMARY KEY, email TEXT, host TEXT, whitelistemail TEXT, blacklistemail TEXT, pattern_type TEXT, score INTEGER, name TEXT, zone TEXT, enabled INTEGER, cache_ttl INTEGER, key TEXT, value TEXT, hash TEXT, prob REAL)');
        }
        $counts = \importRulesInto($db, ['complex_rules' => [
            ['id' => 7, 'email' => '*', 'name' => 'Faktury', 'action' => 'quarantine', 'score' => 2, 'conditions' => ['op' => 'and', 'items' => [['field' => 'subject', 'match' => 'contains', 'value' => 'faktura', 'negate' => false]]]],
            ['id' => 8, 'email' => '*', 'name' => 'Zła', 'action' => 'nope', 'conditions' => []],
        ]]);
        $this->assertSame(1, $counts['complex_rules']);
        $rules = \loadComplexRules($db);
        $this->assertSame('Faktury', $rules[0]['name']);
    }
}
