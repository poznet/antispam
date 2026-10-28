<?php

namespace AntispamBundle\Tests\Services\Bayes;

use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\Bayes\BayesMath;
use AntispamBundle\Services\Bayes\BayesTokenizer;
use AntispamBundle\Services\ScoringService;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The Maildir agent re-implements the tokenizer and the math (single-file,
 * PHP 7.1). Same input -> same tokens, probabilities and points; a synced
 * token table makes the agent score a trained message like the panel.
 */
class BayesAgentParityTest extends BayesTestCase
{
    public static function setUpBeforeClass(): void
    {
        if (!defined('ANTISPAM_AGENT_LIBRARY')) {
            define('ANTISPAM_AGENT_LIBRARY', true);
        }
        require_once __DIR__ . '/../../../Resources/agent/antispam-agent.php';
    }

    public static function fieldCases(): array
    {
        return [
            [['subject' => 'Pilna FAKTURA do zapłaty!!!', 'from' => 'biuro@firma.pl', 'reply_to' => 'x@evil.example', 'message_id' => '<a.1@mx.firma.pl>',
              'x_mailer' => 'PHPMailer 6.8.1', 'content_type' => 'text/plain; charset=utf-8', 'text' => "Zażółć gęślą jaźń https://a.b.example.com/x www.foo.pl/y\nKonstantynopolitańczykowianeczka $100 l'été 2026 co-op"]],
            [['html' => '<html><style>p{}</style><p>Promocja &amp; rabat <a href="http://Sklep.Example.PL/promo">tutaj</a></p></html>']],
            [['subject' => "zly \xC3\x28 bajt", 'text' => str_repeat('słowo ', 50) . implode(' ', range(1, 50))]],
            [[]],
        ];
    }

    #[DataProvider('fieldCases')]
    public function testTokenizerParity(array $fields)
    {
        $this->assertSame(BayesTokenizer::tokenize($fields), \bayesTokenize($fields));
        foreach (BayesTokenizer::tokenize($fields) as $t) {
            $this->assertSame(BayesTokenizer::hash($t), \bayesHash($t));
        }
    }

    public function testConstantsParity()
    {
        $this->assertSame([BayesTokenizer::MAX_TOKENS, BayesTokenizer::MAX_WORD, BayesTokenizer::MIN_WORD, BayesTokenizer::MAX_BODY_BYTES],
            [\BAYES_MAX_TOKENS, \BAYES_MAX_WORD, \BAYES_MIN_WORD, \BAYES_MAX_BODY_BYTES]);
        $this->assertSame([BayesMath::UNKNOWN_STRENGTH, BayesMath::UNKNOWN_PROB, BayesMath::MIN_STRENGTH, BayesMath::MAX_DISCRIMINATORS],
            [\BAYES_UNKNOWN_STRENGTH, \BAYES_UNKNOWN_PROB, \BAYES_MIN_STRENGTH, \BAYES_MAX_DISCRIMINATORS]);
    }

    public function testMathParity()
    {
        foreach ([[0, 0, 10, 10], [1, 0, 10, 10], [5, 50, 100, 300], [300, 2, 400, 400]] as [$s, $h, $ns, $nh]) {
            $this->assertSame(BayesMath::tokenProb($s, $h, $ns, $nh), \bayesTokenProb($s, $h, $ns, $nh));
        }
        foreach ([[2.0, 2], [18.307, 10], [123.4, 300]] as [$x, $v]) {
            $this->assertSame(BayesMath::chi2Q($x, $v), \bayesChi2Q($x, $v));
        }
        $probs = [];
        mt_srand(7);
        for ($i = 0; $i < 400; $i++) {
            $probs[sprintf('%016x', $i)] = mt_rand(1, 999) / 1000;
        }
        $this->assertSame(BayesMath::combine($probs), \bayesCombine($probs));
        $w = ['spam_score' => 5, 'likely_score' => 3, 'ham_score' => 2];
        foreach ([0.999, 0.95, 0.5, 0.005] as $p) {
            $this->assertSame(BayesMath::scoreFor($p, $w), \bayesScoreFor($p, $w));
            $this->assertSame(BayesMath::scoreFor($p, $w, true), \bayesScoreFor($p, $w, true));
        }
        $this->assertSame($w, \bayesWeightsFromSettings([]), 'agent defaults = panel defaults');
        $this->assertSame([\AntispamBundle\Services\Bayes\BayesService::DEFAULT_SPAM_SCORE, \AntispamBundle\Services\Bayes\BayesService::DEFAULT_LIKELY_SCORE, \AntispamBundle\Services\Bayes\BayesService::DEFAULT_HAM_SCORE], array_values($w));
    }

    public function testRawMessageFieldsParity()
    {
        $raw = "From: =?UTF-8?Q?Biuro?= <biuro@firma.pl>\r\nReply-To: <r@inna.pl>\r\nSubject: =?UTF-8?Q?Zap=C5=82ata_faktury?=\r\nMessage-ID: <1@firma.pl>\r\nX-Mailer: Outlook 16\r\n"
            . "Content-Type: text/plain; charset=utf-8\r\n\r\nProsimy o zapłatę faktury https://pay.firma.pl/x\r\n";
        $headers = \readHeaderBlockFromString($raw);
        $file = tempnam(sys_get_temp_dir(), 'bayes');
        file_put_contents($file, $raw);
        try {
            $agent = \bayesTokenize(\bayesFieldsFromHeaders($headers, \parseMessageParts($file)));
        } finally {
            unlink($file);
        }
        $web = BayesTokenizer::tokenize(BayesTokenizer::fieldsFromRaw($raw));
        sort($agent);
        sort($web);
        $this->assertSame($web, $agent);
    }

    /** Export from a trained panel, import into an agent DB, score the same message on both sides. */
    public function testSyncedTableScoresLikeThePanel()
    {
        $bayes = $this->bayes();
        $this->train($bayes);
        $exporter = new AgentRulesExporter($this->em, new ScoringService($this->em, $this->config), null, $bayes);
        $rules = $exporter->export('jan@firma.pl');
        $this->assertTrue($rules['settings']['bayes_enabled']);
        $this->assertNotEmpty($rules['bayes_tokens']);

        $dbPath = sys_get_temp_dir() . '/bayes-agent-' . bin2hex(random_bytes(4)) . '.sqlite';
        try {
            $res = \importRules($dbPath, json_encode($rules));
            $this->assertTrue($res['success'], json_encode($res));
            $this->assertSame(count($rules['bayes_tokens']), $res['imported']['bayes_tokens']);
            $table = \bayesLoadTokens(\getDb($dbPath));

            $raw = self::raw('Wygrana nagroda', 'Odbierz darmową nagrodę, tani kredyt bez BIK https://promo.casino-win.ru/x viagra promocja', 'x@casino-win.ru');
            $fields = BayesTokenizer::fieldsFromRaw($raw);
            $web = $bayes->classifyFields($fields)['p'];
            $agent = \bayesProbability(\bayesTokenize($fields), $table);
            $this->assertEqualsWithDelta($web, $agent, 1e-5, 'probabilities rounded to 6 decimals in the export');
            $this->assertSame(BayesMath::label($web), \bayesLabel($agent));

            $cfg = \scanConfig(array_map(fn($v) => is_bool($v) ? ($v ? '1' : '0') : (string)$v, $rules['settings']), []);
            $this->assertTrue($cfg['bayes']);
            $this->assertFalse(\scanConfig(['bayes_enabled' => '1'], ['no-bayes' => true])['bayes']);

            // disabled in the panel -> the next sync clears the agent's table
            $this->config->set('bayes.enabled', false);
            $rules = $exporter->export('jan@firma.pl');
            $this->assertFalse($rules['settings']['bayes_enabled']);
            \importRules($dbPath, json_encode($rules));
            $this->assertSame([], \bayesLoadTokens(\getDb($dbPath)));
        } finally {
            @unlink($dbPath);
        }
    }

    public function testAgentScanAddsBayesPoints()
    {
        $bayes = $this->bayes();
        $this->train($bayes);
        $rules = (new AgentRulesExporter($this->em, new ScoringService($this->em, $this->config), null, $bayes))->export('jan@firma.pl');
        foreach (['url_enabled', 'cert_enabled', 'dnsbl_enabled', 'impersonation_enabled', 'attachment_policy_enabled', 'header_check_enabled'] as $k) {
            $rules['settings'][$k] = false;
        }
        $dir = sys_get_temp_dir() . '/bayes-maildir-' . bin2hex(random_bytes(4));
        foreach (['Maildir/new', 'Maildir/cur', 'Maildir/tmp'] as $d) {
            mkdir($dir . '/' . $d, 0700, true);
        }
        try {
            \importRules($dir . '/rules.sqlite', json_encode($rules));
            file_put_contents($dir . '/Maildir/new/1.M1.host', str_replace("\r\n", "\n", self::raw('Wygrana nagroda', 'Odbierz darmową nagrodę, tani kredyt bez BIK https://promo.casino-win.ru/x viagra promocja', 'x@casino-win.ru')));
            $res = \runScan($dir . '/Maildir', $dir . '/rules.sqlite', []);
            $this->assertSame(1, $res['quarantined'], json_encode($res));
            $this->assertSame(5, $res['decisions'][0]['score']);
        } finally {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($it as $f) {
                $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
            }
            rmdir($dir);
        }
    }
}
