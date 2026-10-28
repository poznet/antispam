<?php

namespace AntispamBundle\Tests\Services\Jobs;

use AntispamBundle\Command\AgentScanAllCommand;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AccountScanner;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\Jobs\Handler\AccountScanHandler;
use AntispamBundle\Services\ScanLockedException;
use AntispamBundle\Services\SshService;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * "Skanuj" as a background job: batches until INBOX is done (first scan kept
 * "initial" until the end), waiting while the scheduled scan holds the
 * mailbox, and the scheduled scan skipping mailboxes a panel job is scanning.
 */
class AccountScanJobTest extends TestCase
{
    private JobsDatabase $db;
    private Account $account;

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
        $this->account = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP)->setImapHost('imap.firma.pl');
        $this->db->em->persist($this->account);
        $this->db->em->flush();
    }

    private function queueScan(): int
    {
        return $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, [], $this->account, dedupeKey: 'account.scan:' . $this->account->getId())->id;
    }

    private function worker(ImapScanService $imap, ?SshService $ssh = null)
    {
        $scanner = new AccountScanner($this->db->em, $ssh ?? $this->createMock(SshService::class), $imap);
        $w = $this->db->worker([new AccountScanHandler($this->db->em, $scanner)]);
        $w->configure(0, 30);
        return $w;
    }

    private static function pass(int $checked, int $remaining, bool $initial = true, int $total = 2500): array
    {
        return ['total' => $total, 'checked' => $checked, 'skipped' => 0, 'whitelisted' => 0, 'blacklisted' => 1, 'quarantined' => 0,
            'moved_to_spam' => 2, 'remaining' => $remaining, 'errors' => [], 'initial' => $initial];
    }

    private function freshAccount(): Account
    {
        $this->db->em->clear();
        return $this->db->em->find(Account::class, $this->account->getId());
    }

    public function testBigFirstScanRunsInBatchesAndMarksTheAccountOnlyAtTheEnd()
    {
        $id = $this->queueScan();
        $imap = $this->createMock(ImapScanService::class);
        $imap->expects($this->exactly(3))->method('scanAccount')
            ->with($this->isInstanceOf(Account::class), null, $this->isType('float'))
            ->willReturnOnConsecutiveCalls(self::pass(1000, 1500), self::pass(1000, 500), self::pass(500, 0));
        $worker = $this->worker($imap);

        $this->assertSame('queued', $worker->runNext()['status'], 'first batch done, the job re-queues itself');
        $row = $this->db->row($id);
        $this->assertSame([1000, 2500], [(int)$row['progress_done'], (int)$row['progress_total']]);
        $this->assertNull($this->freshAccount()->getLastScanAt(), 'an unfinished first scan stays "initial" (kept out of stats)');

        $worker->runNext();
        $this->assertSame('done', $worker->runNext()['status']);

        $result = json_decode($this->db->row($id)['result'], true);
        $this->assertTrue($result['success']);
        $this->assertSame([2500, 6, 3, 0], [$result['scan_result']['checked'], $result['scan_result']['moved_to_spam'], $result['scan_result']['blacklisted'], $result['scan_result']['remaining']]);
        $account = $this->freshAccount();
        $this->assertNotNull($account->getLastScanAt());
        $this->assertTrue($account->getLastScanResultDecoded()['initial']);
        $this->assertSame(2500, $account->getLastScanResultDecoded()['checked']);
    }

    public function testWaitsWhileTheScheduledScanHoldsTheMailbox()
    {
        $id = $this->queueScan();
        $imap = $this->createMock(ImapScanService::class);
        $imap->method('scanAccount')->willReturnOnConsecutiveCalls(
            $this->throwException(new ScanLockedException()),
            self::pass(10, 0, false, 10),
        );
        $worker = $this->worker($imap);

        $this->assertSame('queued', $worker->runNext()['status']);
        $row = $this->db->row($id);
        $this->assertStringContainsString('Czeka', $row['progress']);
        $this->assertGreaterThan(time() + 20, strtotime($row['available_at']), 'retried later, not in a busy loop');
        $this->assertNull($worker->runNext());

        $this->db->update($id, ['available_at' => (new \DateTime('-1 second'))->format('Y-m-d H:i:s')]);
        $this->assertSame('done', $worker->runNext()['status']);
    }

    public function testSshScanErrorFailsTheJob()
    {
        $this->account->setConnectionType(Account::CONNECTION_SSH)->setAgentDeployed(true);
        $this->db->em->flush();
        $id = $this->queueScan();
        $ssh = $this->createMock(SshService::class);
        $ssh->method('runScan')->willReturn(['success' => false, 'error' => 'Agent nie odpowiedział w ciągu 3600 s']);

        $this->assertSame('failed', $this->worker($this->createMock(ImapScanService::class), $ssh)->runNext()['status']);
        $this->assertStringContainsString('3600 s', $this->db->row($id)['error']);
    }

    public function testDeletedAccountFailsCleanly()
    {
        $id = $this->queueScan();
        $this->db->em->remove($this->account);
        $this->db->em->flush();
        $this->assertSame('failed', $this->worker($this->createMock(ImapScanService::class))->runNext()['status']);
        $this->assertSame('Konto zostało usunięte.', $this->db->row($id)['error']);
    }

    public function testAgentLockedAnswerIsAScanLock()
    {
        $this->account->setConnectionType(Account::CONNECTION_SSH)->setAgentDeployed(true);
        $ssh = $this->createMock(SshService::class);
        $ssh->method('runScan')->willReturn(['success' => false, 'locked' => true, 'error' => 'Another scan is already running for this mailbox']);
        $this->expectException(ScanLockedException::class);
        (new AccountScanner($this->db->em, $ssh, $this->createMock(ImapScanService::class)))->scan($this->account);
    }

    public function testScheduledScanSkipsMailboxesBusyWithAPanelJobOrALock()
    {
        $ola = (new Account())->setName('Ola')->setEmail('ola@firma.pl')->setConnectionType(Account::CONNECTION_IMAP);
        $ewa = (new Account())->setName('Ewa')->setEmail('ewa@firma.pl')->setConnectionType(Account::CONNECTION_IMAP);
        $this->db->em->persist($ola);
        $this->db->em->persist($ewa);
        $this->db->em->flush();
        $this->queueScan(); // jan: queued from the panel

        $imap = $this->createMock(ImapScanService::class);
        $imap->method('isLegacyConfigured')->willReturn(false);
        $imap->expects($this->exactly(2))->method('scanAccount')
            ->with($this->isInstanceOf(Account::class), null, $this->isType('float'))
            ->willReturnCallback(function (Account $a) {
                if ($a->getEmail() === 'ola@firma.pl') {
                    throw new ScanLockedException();
                }
                return self::pass(3, 0, true, 3);
            });
        $command = new AgentScanAllCommand($this->db->em, new AccountScanner($this->db->em, $this->createMock(SshService::class), $imap), $imap, $this->db->queue);
        $tester = new CommandTester($command);

        $this->assertSame(0, $tester->execute([]), 'a busy mailbox is not an error');
        $out = $tester->getDisplay();
        $this->assertStringContainsString('jan@firma.pl (imap): skipped (scan queued from the panel', $out);
        $this->assertStringContainsString('ola@firma.pl (imap): skipped (Skanowanie tej skrzynki już trwa', $out);
        $this->assertStringContainsString('ewa@firma.pl (imap): OK - 3 total', $out);
    }

    public function testScheduledScanLeavesTheRestOfAHugeInboxForTheNextRun()
    {
        $imap = $this->createMock(ImapScanService::class);
        $imap->method('isLegacyConfigured')->willReturn(false);
        $imap->method('scanAccount')->willReturn(self::pass(800, 1700));
        $tester = new CommandTester(new AgentScanAllCommand($this->db->em, new AccountScanner($this->db->em, $this->createMock(SshService::class), $imap), $imap, $this->db->queue));

        $this->assertSame(0, $tester->execute(['--max-seconds' => '60']));
        $this->assertStringContainsString('1700 left for the next run (initial scan)', $tester->getDisplay());
        $this->assertNull($this->freshAccount()->getLastScanAt());
    }
}
