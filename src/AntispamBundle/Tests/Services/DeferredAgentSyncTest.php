<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\Jobs\Handler\AccountSyncHandler;
use AntispamBundle\Services\SshService;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\TestCase;

/**
 * Rule changes in the user area push the rules to SSH agents through a
 * background job (one pending sync per account), never in the request.
 */
class DeferredAgentSyncTest extends TestCase
{
    private JobsDatabase $db;
    /** @var array<int, Account> */
    private array $accounts = [];

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
        foreach ([
            ['jan@ssh.pl', Account::CONNECTION_SSH, true],
            ['jan@ssh.pl', Account::CONNECTION_SSH, false],
            ['jan@ssh.pl', Account::CONNECTION_IMAP, false],
            ['ola@ssh.pl', Account::CONNECTION_SSH, true],
        ] as [$email, $type, $deployed]) {
            $a = (new Account())->setName($email)->setEmail($email)->setConnectionType($type)->setAgentDeployed($deployed);
            $this->db->em->persist($a);
            $this->accounts[] = $a;
        }
        $this->db->em->flush();
    }

    private function exporter(): AgentRulesExporter
    {
        $exporter = $this->createMock(AgentRulesExporter::class);
        $exporter->method('export')->willReturnCallback(fn($email) => ['owner' => $email]);
        return $exporter;
    }

    public function testOnlyDeployedSshAccountsOfTheOwnerAreQueued()
    {
        $sync = new DeferredAgentSync($this->db->em, $this->db->queue);
        $this->assertSame(1, $sync->deferForOwner('jan@ssh.pl'));
        $this->assertSame(0, $sync->deferForOwner('*'), 'global rules are never pushed from the user area');
        $this->assertFalse($sync->defer($this->accounts[2]), 'IMAP accounts read the database');

        $this->assertSame(1, $sync->deferForOwner('jan@ssh.pl'), 'a second change is accepted ...');
        $jobs = $this->db->em->getConnection()->fetchAllAssociative('SELECT type, account_id, payload FROM antispam_job');
        $this->assertSame([[
            'type' => BackgroundJob::TYPE_ACCOUNT_SYNC, 'account_id' => $this->accounts[0]->getId(), 'payload' => '{"background":true}',
        ]], $jobs, '... but only one sync per account waits in the queue');
    }

    public function testChangeDuringARunningSyncQueuesAnotherOne()
    {
        $sync = new DeferredAgentSync($this->db->em, $this->db->queue);
        $sync->defer($this->accounts[0]);
        $ssh = $this->createMock(SshService::class);
        // While the first sync runs (it may have exported the old rules), the user changes a rule again.
        $ssh->method('syncRules')->willReturnCallback(function () use ($sync) {
            $sync->defer($this->accounts[0]);
            return ['success' => true];
        });
        $worker = $this->db->worker([new AccountSyncHandler($this->db->em, $ssh, $this->exporter())]);

        $this->assertSame('done', $worker->runNext()['status']);
        $this->assertSame('queued', $this->db->row(2)['status'], 'sync jobs are not exclusive while running');
    }

    public function testFailedBackgroundSyncIsAFailedJob()
    {
        (new DeferredAgentSync($this->db->em, $this->db->queue))->defer($this->accounts[3]);
        $ssh = $this->createMock(SshService::class);
        $ssh->expects($this->once())->method('syncRules')->with($this->accounts[3], json_encode(['owner' => 'ola@ssh.pl']))
            ->willReturn(['success' => false, 'error' => 'agent old']);

        $this->assertSame('failed', $this->db->worker([new AccountSyncHandler($this->db->em, $ssh, $this->exporter())])->runNext()['status']);
        $this->assertStringContainsString('agent old', $this->db->row(1)['error']);
    }
}
