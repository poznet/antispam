<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\AccountDailyStat;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\AccountStatsService;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\TestCase;

class AccountStatsServiceTest extends TestCase
{
    private JobsDatabase $db;
    private AccountStatsService $stats;

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
        $this->stats = new AccountStatsService($this->db->em);
    }

    public function testRecordSumsPassesPerDayAndKind()
    {
        $this->stats->record(7, AccountDailyStat::KIND_SCAN, ['checked' => 10, 'moved_to_spam' => 2, 'quarantined' => 1, 'whitelisted' => 3, 'errors' => ['x', 'y']]);
        $this->stats->record(7, AccountDailyStat::KIND_SCAN, ['checked' => 5, 'moved_to_spam' => 1]);
        $this->stats->record(7, AccountDailyStat::KIND_RESCAN, ['checked' => 100, 'quarantined' => 4]);
        $this->stats->record(7, AccountDailyStat::KIND_SCAN, ['checked' => 50], new \DateTimeImmutable('-40 days'));
        $this->stats->record(8, AccountDailyStat::KIND_SCAN, ['checked' => 999]);
        $this->stats->record(7, 'nope', ['checked' => 1]);

        $t = $this->stats->totals(7, AccountStatsService::since(30));
        $this->assertSame(115, $t['all']['checked']);
        $this->assertSame(3, $t['all']['moved_to_spam']);
        $this->assertSame(5, $t['all']['quarantined']);
        $this->assertSame(2, $t['all']['errors']);
        $this->assertSame(3, $t['all']['passes']);
        $this->assertSame(['scan', 'rescan'], array_keys($t['kinds']));
        $this->assertSame(2, $t['kinds']['scan']['passes']);

        $this->assertSame(165, $this->stats->totals(7, null)['all']['checked']);

        $daily = $this->stats->daily(7, 30);
        $this->assertCount(30, $daily);
        $this->assertSame(115, end($daily)['checked']);
        $this->assertSame(0, reset($daily)['checked']);

        $this->stats->forget(7);
        $this->assertSame(0, $this->stats->totals(7, null)['all']['checked']);
        $this->assertSame(999, $this->stats->totals(8, null)['all']['checked']);
    }

    public function testScoreLogBreakdown()
    {
        $em = $this->db->em;
        $add = function ($decision, $sender, $reasons, $source = SpamScoreLog::SOURCE_SCAN, $outcome = null, $email = 'jan@firma.pl') use ($em) {
            $em->persist((new SpamScoreLog())->setAccountEmail($email)->setSender($sender)->setSubject('t')->setScore(10)
                ->setDecision($decision)->setReasons($reasons)->setSource($source)->setOutcome($outcome));
        };
        $add('spam', 'a@spam.ru', [['rule' => 'blacklist:*.ru (wildcard)', 'score' => 10], ['rule' => 'dnsbl:zen', 'score' => 5]], SpamScoreLog::SOURCE_SCAN, SpamScoreLog::OUTCOME_SPAM_FOLDER);
        $add('spam', 'b@spam.ru', [['rule' => 'blacklist:*.ru (wildcard)', 'score' => 10]], SpamScoreLog::SOURCE_SCAN, SpamScoreLog::OUTCOME_SPAM_FOLDER);
        $add('quarantine', 'a@spam.ru', [['rule' => 'complex_rule:#3 Faktury (quarantine)', 'score' => 5]], SpamScoreLog::SOURCE_PLUGIN);
        $add('ham', 'c@ok.pl', []);
        $add('spam', 'x@other.pl', [], SpamScoreLog::SOURCE_SCAN, null, 'inny@firma.pl');
        $em->flush();

        $log = $this->stats->scoreLog('jan@firma.pl', AccountStatsService::since(30));
        $this->assertSame(4, $log['total']);
        $this->assertEquals(['spam' => 2, 'quarantine' => 1, 'ham' => 1], $log['decisions']);
        $this->assertSame(1, $log['sources']['plugin']['quarantine']);
        $this->assertSame(2, $log['outcomes']['spam_folder']);
        $this->assertSame(['a@spam.ru' => 2, 'b@spam.ru' => 1], $log['senders']);
        $this->assertSame(['spam.ru' => 3], $log['domains']);
        $this->assertSame(2, $log['rules']['blacklist:*.ru (wildcard)']);
        $this->assertEquals(['blacklist' => 2, 'dnsbl' => 1, 'complex_rule' => 1], $log['categories']);
        $this->assertCount(3, $log['recent']);
    }

    public function testRuleCategory()
    {
        $this->assertSame('complex_rule', AccountStatsService::ruleCategory('complex_rule:#3 X (spam)'));
        $this->assertSame('header_cap', AccountStatsService::ruleCategory('header_cap'));
        $this->assertSame('inne', AccountStatsService::ruleCategory(':x'));
    }
}
