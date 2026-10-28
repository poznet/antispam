<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\Jobs\Handler\RetroactiveRuleHandler;
use AntispamBundle\Services\RetroactiveSpamService;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\TestCase;

/**
 * The retroactive pass of a new rule (panel forms, phishing page, plugin
 * reports) is a background job: queued once per rule, run by the worker.
 */
class DeferredRetroactivePassTest extends TestCase
{
    private JobsDatabase $db;

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
    }

    private function rule(string $sender = 'spam@evil.top'): EmailBlacklist
    {
        $rule = (new EmailBlacklist())->setEmail('jan@firma.pl')->setBlacklistemail($sender)->setPatternType('exact')->setCounter(0);
        $rule->setScore(10);
        $this->db->em->persist($rule);
        $this->db->em->flush();
        return $rule;
    }

    public function testQueuesOneJobPerRuleWithPayloadAndOwner()
    {
        $pass = new DeferredRetroactivePass($this->db->queue);
        $rule = $this->rule();

        $first = $pass->queue($rule, 'admin', 'env_admin');
        $second = $pass->queue($rule);
        $this->assertTrue($first->created);
        $this->assertFalse($second->created, 'the same rule is not queued twice');
        $this->assertSame($first->id, $second->id);

        $row = $this->db->row($first->id);
        $this->assertSame(BackgroundJob::TYPE_RULE_RETROACTIVE, $row['type']);
        $this->assertSame(['rule' => 'email_blacklist', 'id' => $rule->getId()], json_decode($row['payload'], true));
        $this->assertSame('jan@firma.pl', $row['mailbox']);
        $this->assertSame('admin', $row['requested_by']);
    }

    public function testPluginRuleIsRequestedByTheMailbox()
    {
        (new DeferredRetroactivePass($this->db->queue))->defer($this->rule());
        $row = $this->db->row(1);
        $this->assertSame(['jan@firma.pl', 'plugin'], [$row['requested_by'], $row['requested_by_type']]);
    }

    public function testUnsavedRuleIsNotQueued()
    {
        $this->assertNull((new DeferredRetroactivePass($this->db->queue))->queue(new Blacklist()));
    }

    public function testWorkerAppliesTheRuleAndStoresTheSummary()
    {
        $rule = $this->rule();
        (new DeferredRetroactivePass($this->db->queue))->queue($rule);
        $retro = $this->createMock(RetroactiveSpamService::class);
        $retro->expects($this->once())->method('applyRule')->with($this->callback(fn($r) => $r->getId() === $rule->getId()))
            ->willReturn(['moved' => 3, 'errors' => [], 'skipped' => null]);

        $this->assertSame(['id' => 1, 'status' => 'done'], $this->db->worker([new RetroactiveRuleHandler($this->db->em, $retro)])->runNext());
        $result = json_decode($this->db->row(1)['result'], true);
        $this->assertSame(3, $result['moved']);
        $this->assertStringContainsString('Przeniesiono do SPAM 3', $result['summary']);
        $this->assertNull($this->db->row(1)['active_key'], 'a finished pass frees the dedupe key');
    }

    public function testRuleDeletedBeforeTheWorkerRanIsSkipped()
    {
        $rule = $this->rule();
        (new DeferredRetroactivePass($this->db->queue))->queue($rule);
        $this->db->em->remove($rule);
        $this->db->em->flush();
        $this->db->em->clear();
        $retro = $this->createMock(RetroactiveSpamService::class);
        $retro->expects($this->never())->method('applyRule');

        $this->assertSame('done', $this->db->worker([new RetroactiveRuleHandler($this->db->em, $retro)])->runNext()['status']);
        $this->assertSame(0, json_decode($this->db->row(1)['result'], true)['moved']);
    }
}
