<?php

namespace AntispamBundle\Tests\Services\Jobs;

use AntispamBundle\Command\RescanDueCommand;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AccountScanner;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\Jobs\Handler\AccountRescanHandler;
use AntispamBundle\Services\RescanScheduler;
use AntispamBundle\Services\ScanLockedException;
use AntispamBundle\Services\SshService;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Full rescan of a mailbox as a background job (batches + resume with its own
 * cursor, the account's scan cursor and last scan untouched, result stored
 * on the account, audit), SSH agent batches and old agents, dedupe, and the
 * weekly schedule (antispam:rescan:due).
 */
class AccountRescanJobTest extends TestCase
{
    private JobsDatabase $db;
    private Account $account;
    /** @var list<array{0:string, 1:array}> audit log calls (action, positional args: targetType, targetId, label, mailbox, details...) */
    private array $audits = [];

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
        $this->account = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP)->setImapHost('imap.firma.pl');
        $this->account->setImapCursor(['uidvalidity' => 777, 'last_uid' => 4000]);
        $this->account->markScanned(['checked' => 5]);
        $this->db->em->persist($this->account);
        $this->db->em->flush();
        $this->audits = [];
    }

    private function audit(): AuditLogger
    {
        $audit = $this->createMock(AuditLogger::class);
        $audit->method('log')->willReturnCallback(function (string $action, ...$args) {
            $this->audits[] = [$action, $args];
        });
        $audit->method('currentActor')->willReturn(['admin', 'user', 'ROLE_ADMIN']);
        return $audit;
    }

    private function scheduler(): RescanScheduler
    {
        return new RescanScheduler($this->db->em, $this->db->queue, $this->audit());
    }

    private function worker(ImapScanService $imap, ?SshService $ssh = null)
    {
        $scanner = new AccountScanner($this->db->em, $ssh ?? $this->createMock(SshService::class), $imap);
        $w = $this->db->worker([new AccountRescanHandler($this->db->em, $scanner)], $this->audit());
        $w->configure(0, 30);
        return $w;
    }

    private static function pass(int $checked, int $remaining, ?array $cursor, int $spam = 2): array
    {
        return ['total' => 2500, 'checked' => $checked, 'skipped' => 0, 'whitelisted' => 1, 'blacklisted' => 1, 'quarantined' => 1,
            'moved_to_spam' => $spam, 'remaining' => $remaining, 'errors' => [], 'cursor' => $cursor];
    }

    private function freshAccount(): Account
    {
        $this->db->em->clear();
        return $this->db->em->find(Account::class, $this->account->getId());
    }

    public function testImapRescanRunsInBatchesWithItsOwnCursor()
    {
        $id = $this->scheduler()->enqueue($this->account)->id;
        $c1 = ['uidvalidity' => 777, 'last_uid' => 1000, 'until_uid' => 2500];
        $c2 = ['uidvalidity' => 777, 'last_uid' => 2000, 'until_uid' => 2500];
        $imap = $this->createMock(ImapScanService::class);
        $imap->expects($this->never())->method('scanAccount');
        $calls = [];
        $imap->expects($this->exactly(3))->method('rescanAccount')
            ->willReturnCallback(function (Account $a, ?array $cursor, ?int $max, ?float $deadline) use (&$calls, $c1, $c2) {
                $calls[] = $cursor;
                $this->assertIsFloat($deadline);
                return [self::pass(1000, 1500, $c1), self::pass(1000, 500, $c2), self::pass(500, 0, null, 0)][count($calls) - 1];
            });
        $worker = $this->worker($imap);

        $this->assertSame('queued', $worker->runNext()['status'], 'first batch done, the job re-queues itself');
        $row = $this->db->row($id);
        $this->assertSame([1000, 2500], [(int)$row['progress_done'], (int)$row['progress_total']]);
        $this->assertNull($this->freshAccount()->getLastRescanAt(), 'not finished yet');
        $this->assertSame('account.rescan:' . $this->account->getId(), $row['active_key'], 'still deduped between batches');

        $worker->runNext();
        $this->assertSame('done', $worker->runNext()['status']);
        $this->assertSame([null, $c1, $c2], $calls, 'every batch continues from the previous cursor');

        $result = json_decode($this->db->row($id)['result'], true);
        $this->assertTrue($result['success']);
        $this->assertSame([2500, 4, 3, 0], [$result['scan_result']['checked'], $result['scan_result']['moved_to_spam'], $result['scan_result']['quarantined'], $result['scan_result']['remaining']]);
        $this->assertArrayNotHasKey('cursor', $result['scan_result']);

        $account = $this->freshAccount();
        $this->assertNotNull($account->getLastRescanAt());
        $this->assertSame(2500, $account->getLastRescanResultDecoded()['checked']);
        $this->assertSame('panel', $account->getLastRescanResultDecoded()['trigger']);
        $this->assertSame($id, $account->getLastRescanResultDecoded()['job']);
        // The regular scan state is untouched: cursor, last scan (dashboard) and its counters.
        $this->assertSame(['uidvalidity' => 777, 'last_uid' => 4000], $account->getImapCursor());
        $this->assertSame(5, $account->getLastScanResultDecoded()['checked']);

        $actions = array_column($this->audits, 0);
        $this->assertSame(['account.rescan_queued', 'account.rescan'], $actions);
        $this->assertTrue($this->audits[1][1][4]['ok']);
        $this->assertSame(4, $this->audits[1][1][4]['moved_to_spam']);
        $this->assertSame($id, $this->audits[1][1][4]['job']);
    }

    public function testWaitsWhileTheMailboxIsLocked()
    {
        $id = $this->scheduler()->enqueue($this->account)->id;
        $imap = $this->createMock(ImapScanService::class);
        $imap->method('rescanAccount')->willReturnOnConsecutiveCalls(
            $this->throwException(new ScanLockedException()),
            self::pass(10, 0, null),
        );
        $worker = $this->worker($imap);

        $this->assertSame('queued', $worker->runNext()['status']);
        $this->assertStringContainsString('Czeka', $this->db->row($id)['progress']);
        $this->assertNull($worker->runNext(), 'retried later');
        $this->db->update($id, ['available_at' => (new \DateTime('-1 second'))->format('Y-m-d H:i:s')]);
        $this->assertSame('done', $worker->runNext()['status']);
    }

    public function testFailureIsStoredOnTheAccount()
    {
        $id = $this->scheduler()->enqueue($this->account)->id;
        $imap = $this->createMock(ImapScanService::class);
        $imap->method('rescanAccount')->willThrowException(new \RuntimeException('IMAP login failed'));

        $this->assertSame('failed', $this->worker($imap)->runNext()['status']);
        $this->assertSame('IMAP login failed', $this->db->row($id)['error']);
        $account = $this->freshAccount();
        $this->assertNotNull($account->getLastRescanAt(), 'a failed rescan still counts for the weekly schedule');
        $this->assertSame('IMAP login failed', $account->getLastRescanResultDecoded()['error']);
        $this->assertFalse($this->audits[1][1][4]['ok']);
    }

    public function testSshRescanResetsOnTheFirstBatchOnly()
    {
        $this->account->setConnectionType(Account::CONNECTION_SSH)->setAgentDeployed(true);
        $this->db->em->flush();
        $id = $this->scheduler()->enqueue($this->account)->id;
        $ssh = $this->createMock(SshService::class);
        $ssh->expects($this->never())->method('runScan');
        $resets = [];
        $ssh->expects($this->exactly(2))->method('runRescan')
            ->willReturnCallback(function (Account $a, bool $reset, int $limit) use (&$resets) {
                $resets[] = $reset;
                $this->assertGreaterThanOrEqual(10, $limit);
                $base = ['success' => true, 'rescan' => true, 'total' => 300, 'skipped' => 0, 'whitelisted' => 0, 'blacklisted' => 3, 'quarantined' => 1,
                    'moved_to_spam' => 3, 'move_failed' => 0, 'errors' => [], 'decisions' => [['file' => 'x']], 'agent_version' => '3.3'];
                return count($resets) === 1 ? ['checked' => 200, 'remaining' => 100] + $base : ['checked' => 100, 'remaining' => 0] + $base;
            });
        $worker = $this->worker($this->createMock(ImapScanService::class), $ssh);

        $this->assertSame('queued', $worker->runNext()['status']);
        $this->assertSame('done', $worker->runNext()['status']);
        $this->assertSame([true, false], $resets, '--reset starts the rescan, later batches continue in the agent');
        $result = json_decode($this->db->row($id)['result'], true)['scan_result'];
        $this->assertSame([300, 6, 0], [$result['checked'], $result['moved_to_spam'], $result['move_failed']]);
        $this->assertArrayNotHasKey('decisions', $result);
    }

    public function testOldAgentAsksForARedeploy()
    {
        $this->account->setConnectionType(Account::CONNECTION_SSH)->setAgentDeployed(true);
        $this->db->em->flush();
        $id = $this->scheduler()->enqueue($this->account)->id;
        // What SshService::interpret() makes of a 3.2 agent's usage text.
        $ssh = (new \ReflectionClass(SshService::class))->newInstanceWithoutConstructor();
        $answer = $ssh->interpret('rescan', ['output' => "Antispam Maildir Agent 3.2\nUsage:\n  php antispam-agent.php test\n", 'stderr' => '', 'exit' => 0, 'timeout' => false], 3600);
        $this->assertStringContainsString('wdróż go ponownie', $answer['error']);

        $mock = $this->createMock(SshService::class);
        $mock->method('runRescan')->willReturn($answer);
        $this->assertSame('failed', $this->worker($this->createMock(ImapScanService::class), $mock)->runNext()['status']);
        $this->assertStringContainsString('nie obsługuje polecenia "rescan"', $this->db->row($id)['error']);
        $this->assertStringContainsString('wdróż go ponownie', $this->freshAccount()->getLastRescanResultDecoded()['error']);
    }

    public function testAgentAnswerWithoutRescanSupportIsAnError()
    {
        // A scan answer (no 'rescan' flag) must never be taken for a finished rescan.
        $this->account->setConnectionType(Account::CONNECTION_SSH)->setAgentDeployed(true);
        $ssh = $this->createMock(SshService::class);
        $ssh->method('runRescan')->willReturn(['success' => true, 'total' => 3, 'checked' => 0]);
        $this->expectException(\RuntimeException::class);
        (new AccountScanner($this->db->em, $ssh, $this->createMock(ImapScanService::class)))->rescan($this->account, null, true, microtime(true) + 60);
    }

    public function testDedupeOneRescanPerAccount()
    {
        $scheduler = $this->scheduler();
        $first = $scheduler->enqueue($this->account);
        $again = $scheduler->enqueue($this->account, RescanScheduler::TRIGGER_SCHEDULE);
        $this->assertTrue($first->created);
        $this->assertFalse($again->created);
        $this->assertSame($first->id, $again->id);
        $this->assertSame(['account.rescan_queued'], array_column($this->audits, 0), 'the reused job is not audited again');

        $other = (new Account())->setName('Ola')->setEmail('ola@firma.pl');
        $this->db->em->persist($other);
        $this->db->em->flush();
        $this->assertTrue($scheduler->enqueue($other)->created);
    }

    public function testPluginRescanIsRequestedByTheMailbox()
    {
        $queued = $this->scheduler()->enqueue($this->account, RescanScheduler::TRIGGER_PLUGIN);
        $row = $this->db->row($queued->id);

        $this->assertSame('jan@firma.pl', $row['requested_by']);
        $this->assertSame('plugin', $row['requested_by_type']);
        $this->assertSame('account.rescan_queued', $this->audits[0][0]);
        $this->assertSame(['jan@firma.pl', 'plugin'], array_slice($this->audits[0][1], 5, 2));
        $this->assertSame(['trigger' => 'plugin'], json_decode($row['payload'], true));
    }

    /** @return iterable<string, array{0:string, 1:?string, 2:bool}> now, last rescan, due */
    public static function schedule(): iterable
    {
        // Slot: Sunday 02:00 (defaults). 2026-11-01 is a Sunday.
        yield 'before the slot' => ['2026-11-01 01:59', null, false];
        yield 'slot started, never rescanned' => ['2026-11-01 02:00', null, true];
        yield 'later that day' => ['2026-11-01 19:00', null, true];
        yield 'rescanned before the slot' => ['2026-11-01 03:00', '2026-10-31 23:00', true];
        yield 'already rescanned this week' => ['2026-11-01 04:00', '2026-11-01 02:30', false];
        yield 'window passed (scheduler was down)' => ['2026-11-02 03:00', '2026-10-20 02:30', false];
        yield 'mid-week after the slot' => ['2026-11-04 12:00', '2026-11-01 02:40', false];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('schedule')]
    public function testWeeklySlot(string $now, ?string $last, bool $due)
    {
        $account = (new Account())->setEmail('x@firma.pl')->setAutoRescan(true);
        if ($last !== null) {
            $account->markRescanned([], new \DateTimeImmutable($last));
        }
        $this->assertSame($due, RescanScheduler::isDue($account, new \DateTimeImmutable($now)));
    }

    public function testCustomDayAndHourAndSwitches()
    {
        $account = (new Account())->setEmail('x@firma.pl')->setAutoRescan(true)->setRescanWeekday(3)->setRescanHour(22);
        $this->assertFalse(RescanScheduler::isDue($account, new \DateTimeImmutable('2026-10-28 21:59')));
        $this->assertTrue(RescanScheduler::isDue($account, new \DateTimeImmutable('2026-10-28 22:05')));
        $this->assertEquals(new \DateTimeImmutable('2026-11-04 22:00'), RescanScheduler::nextSlot($account, new \DateTimeImmutable('2026-10-28 22:05')));
        $this->assertFalse(RescanScheduler::isDue($account->setAutoRescan(false), new \DateTimeImmutable('2026-10-28 22:05')), 'off by default / switched off');
        $ssh = (new Account())->setEmail('s@firma.pl')->setConnectionType(Account::CONNECTION_SSH)->setAutoRescan(true)->setRescanWeekday(3)->setRescanHour(22);
        $this->assertFalse(RescanScheduler::isDue($ssh, new \DateTimeImmutable('2026-10-28 22:05')), 'SSH without a deployed agent');
        $this->assertNull((new Account())->setRescanHour(24)->getRescanHour());
    }

    public function testDueCommandQueuesOnlyDueAccountsOnce()
    {
        // Due now: slot = today, this hour.
        $now = new \DateTimeImmutable();
        $this->account->setAutoRescan(true)->setRescanWeekday((int)$now->format('N'))->setRescanHour((int)$now->format('G'));
        $off = (new Account())->setName('Ola')->setEmail('ola@firma.pl')->setRescanWeekday((int)$now->format('N'))->setRescanHour((int)$now->format('G'));
        $this->db->em->persist($off);
        $this->db->em->flush();

        $tester = new CommandTester(new RescanDueCommand($this->db->em, $this->scheduler()));
        $this->assertSame(0, $tester->execute(['--dry-run' => true]));
        $this->assertStringContainsString('jan@firma.pl (imap): due', $tester->getDisplay());
        $this->assertSame(0, (int)$this->db->em->getConnection()->fetchOne('SELECT COUNT(*) FROM antispam_job'));

        $this->assertSame(0, $tester->execute([]));
        $this->assertStringContainsString('jan@firma.pl (imap): rescan queued (job #1)', $tester->getDisplay());
        $this->assertStringNotContainsString('ola@', $tester->getDisplay(), 'weekly rescan is off by default');
        $row = $this->db->row(1);
        $this->assertSame([BackgroundJob::TYPE_ACCOUNT_RESCAN, 'harmonogram'], [$row['type'], $row['requested_by']]);
        $this->assertSame(['trigger' => 'schedule'], json_decode($row['payload'], true));

        $tester->execute([]);
        $this->assertStringContainsString('rescan already queued (job #1)', $tester->getDisplay(), 'hourly re-run while queued: deduped');

        // Once it finished this week, nothing is due any more.
        $this->db->update(1, ['status' => 'done', 'active_key' => null]);
        $this->freshAccount()->markRescanned(['checked' => 1]);
        $this->db->em->flush();
        $tester->execute([]);
        $this->assertStringContainsString('No rescan due.', $tester->getDisplay());

        $tester->execute(['--account' => (string)$off->getId()]);
        $this->assertStringContainsString('ola@firma.pl (imap): rescan queued', $tester->getDisplay());
        $this->assertSame(\Symfony\Component\Console\Command\Command::INVALID, $tester->execute(['--account' => '999']));
    }
}
