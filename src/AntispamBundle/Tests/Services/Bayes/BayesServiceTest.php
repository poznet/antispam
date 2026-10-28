<?php

namespace AntispamBundle\Tests\Services\Bayes;

use AntispamBundle\Entity\BayesToken;
use AntispamBundle\Services\Bayes\BayesStore;
use AntispamBundle\Services\Bayes\BayesTokenizer;

class BayesServiceTest extends BayesTestCase
{
    private function store(): BayesStore
    {
        return new BayesStore($this->em->getConnection());
    }

    public function testLearningCountsTokensAndMessages()
    {
        $bayes = $this->bayes();
        $raw = self::spamCorpus(1)[0];
        $r = $bayes->learnRaw($raw, 'spam', null, 'test');
        $this->assertTrue($r['learned']);
        $this->assertSame(['spam' => 1, 'ham' => 0], $this->store()->totals(0));

        $hex = BayesTokenizer::hash('nagrodę');
        $this->assertSame([$hex => [1, 0]], $this->store()->counts(0, [$hex, BayesTokenizer::hash('nieznane-slowo')]));
        $this->assertSame($r['tokens'], $bayes->stats()['tokens']);

        // the same verdict twice changes nothing
        $this->assertFalse($bayes->learnRaw($raw, 'spam')['learned']);
        $this->assertSame(['spam' => 1, 'ham' => 0], $this->store()->totals(0));
    }

    public function testReversedVerdictIsUnlearnedFirst()
    {
        $bayes = $this->bayes();
        $raw = self::spamCorpus(1)[0];
        $bayes->learnRaw($raw, 'spam');
        $r = $bayes->learnRaw($raw, 'ham', null, 'quarantine');
        $this->assertTrue($r['learned']);
        $this->assertTrue($r['reversed']);
        $this->assertSame(['spam' => 0, 'ham' => 1], $this->store()->totals(0));
        $hex = BayesTokenizer::hash('nagrodę');
        $this->assertSame([$hex => [0, 1]], $this->store()->counts(0, [$hex]));
        $this->assertSame('ham', $this->store()->learnedVerdict(0, \AntispamBundle\Services\Bayes\BayesService::fingerprint(BayesTokenizer::fieldsFromRaw($raw), [])));
    }

    public function testDisabledLearnsNothingAndScoresNothing()
    {
        $this->config->set('bayes.enabled', false);
        $bayes = $this->bayes();
        $this->assertSame('disabled', $bayes->learnRaw(self::spamCorpus(1)[0], 'spam')['reason']);
        $this->assertSame(0, $bayes->stats()['spam']);
        $this->assertNull($bayes->scoreFields(BayesTokenizer::fieldsFromRaw(self::spamCorpus(1)[0]))['reason']);
    }

    public function testScoringNeedsMinimumTraining()
    {
        $bayes = $this->bayes();
        $spam = BayesTokenizer::fieldsFromRaw(self::raw('Darmowa nagroda czeka', 'Odbierz nagrodę, tani kredyt bez BIK https://x.casino-win.ru/a viagra promocja', 'n@casino-win.ru'));

        foreach (array_slice(self::spamCorpus(), 0, 4) as $raw) {
            $bayes->learnRaw($raw, 'spam');
        }
        foreach (self::hamCorpus() as $raw) {
            $bayes->learnRaw($raw, 'ham');
        }
        $c = $bayes->classifyFields($spam);
        $this->assertFalse($c['ready'], '4 spam < min 5');
        $this->assertNull($bayes->scoreFields($spam)['reason']);

        $this->train($bayes);
        $this->assertTrue($bayes->stats()['ready']);
        $result = $bayes->scoreFields($spam);
        $this->assertSame(5, $result['score']);
        $this->assertMatchesRegularExpression('/^bayes:0\.9\d$/', $result['reason']['rule']);
        $this->assertGreaterThanOrEqual(0.99, $result['p']);

        $ham = BayesTokenizer::fieldsFromRaw(self::raw('Raport i faktura', 'Cześć, raport kwartalny i faktura w załączniku, spotkanie w czwartek. Pozdrawiam, Anna', 'anna@firma.pl'));
        $this->assertSame(-2, $bayes->scoreFields($ham)['score']);
        $this->assertSame(0, $bayes->scoreFields($ham, null, true)['score'], 'blacklisted sender keeps its score');
    }

    public function testPerMailboxScope()
    {
        $this->config->set('bayes.per_mailbox', true);
        $jan = $this->account('jan@firma.pl');
        $bayes = $this->bayes();
        $this->train($bayes, 'jan@firma.pl');

        $this->assertSame(['spam' => 6, 'ham' => 6], $this->store()->totals(0), 'global always learns');
        $this->assertSame(['spam' => 6, 'ham' => 6], $this->store()->totals($jan->getId()));
        $fields = BayesTokenizer::fieldsFromRaw(self::spamCorpus(1)[0]);
        $this->assertSame($jan->getId(), $bayes->classifyFields($fields, 'jan@firma.pl')['scope']);
        $this->assertSame(0, $bayes->classifyFields($fields, 'other@firma.pl')['scope'], 'no own data -> global');
        $this->assertSame(1, $bayes->stats()['scopes']);
    }

    public function testExportForAgent()
    {
        $bayes = $this->bayes();
        $this->assertFalse($bayes->exportForAgent(null)['enabled'], 'untrained');
        $this->train($bayes);
        $this->config->set('bayes.agent_max_tokens', 10);
        $export = $bayes->exportForAgent('jan@firma.pl');
        $this->assertTrue($export['enabled']);
        $this->assertCount(10, $export['tokens']);
        foreach ($export['tokens'] as [$hex, $p]) {
            $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $hex);
            $this->assertGreaterThanOrEqual(0.1, abs($p - 0.5));
        }
    }

    public function testResetAndPurge()
    {
        $bayes = $this->bayes();
        $jan = $this->account('jan@firma.pl');
        $this->config->set('bayes.per_mailbox', true);
        $this->train($bayes, 'jan@firma.pl');
        $db = $this->em->getConnection();

        // a hapax not touched for a year, an old fingerprint, a deleted mailbox's scope
        $db->executeStatement('UPDATE ' . BayesToken::TABLE . " SET updated_at = '2020-01-01 00:00:00' WHERE scope = 0 AND spam_count + ham_count = 1 AND token_hash <> 0");
        $db->executeStatement("UPDATE antispam_bayes_message SET learned_at = '2020-01-01 00:00:00' WHERE scope = 0");
        $db->insert(BayesToken::TABLE, ['scope' => 999, 'token_hash' => 5, 'spam_count' => 3, 'ham_count' => 0, 'updated_at' => (new \DateTime())->format('Y-m-d H:i:s')]);
        $hapaxes = (int)$db->fetchOne('SELECT COUNT(*) FROM ' . BayesToken::TABLE . " WHERE scope = 0 AND updated_at < '2021-01-01'");
        $this->assertGreaterThan(0, $hapaxes);

        $r = $bayes->purge();
        $this->assertSame(12, $r['messages']);
        $this->assertSame($hapaxes, $r['tokens']);
        $this->assertSame(1, $r['orphans']);
        $this->assertSame(['spam' => 6, 'ham' => 6], $this->store()->totals(0), 'message totals stay');
        $this->assertSame(['spam' => 6, 'ham' => 6], $this->store()->totals($jan->getId()));

        $this->assertGreaterThan(0, $bayes->reset());
        $this->assertSame(['tokens' => 0, 'tokens_all' => 0, 'spam' => 0, 'ham' => 0, 'scopes' => 0, 'messages' => 0], array_intersect_key($bayes->stats(), array_flip(['tokens', 'tokens_all', 'spam', 'ham', 'scopes', 'messages'])));
    }

    public function testPurgeCommandRunsTheBayesBlock()
    {
        $bayes = $this->bayes();
        $this->train($bayes);
        $this->em->getConnection()->executeStatement("UPDATE antispam_bayes_message SET learned_at = '2020-01-01 00:00:00'");
        $tester = new \Symfony\Component\Console\Tester\CommandTester(new \AntispamBundle\Command\PurgeCommand($this->em, $this->config, $bayes));
        $this->assertSame(0, $tester->execute(['--dry-run' => true]));
        $this->assertStringContainsString('Bayes: skipped in --dry-run.', $tester->getDisplay());
        $this->assertSame(0, $tester->execute([]));
        $this->assertStringContainsString('Bayes: deleted 12 learned-message fingerprint(s)', $tester->getDisplay());
    }
}
