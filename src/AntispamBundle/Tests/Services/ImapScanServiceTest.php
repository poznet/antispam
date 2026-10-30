<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\EventListener\Message\CheckIfIsAlreadyChecked;
use AntispamBundle\EventListener\Message\SetAsChecked;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\Jobs\JobCancellation;
use AntispamBundle\Services\MessageService;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\Exception\InvalidSearchCriteriaException;
use Ddeboer\Imap\ImapResourceInterface;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\MessageInterface;
use Ddeboer\Imap\MessageIterator;
use Ddeboer\Imap\Search\ConditionInterface;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Filesystem\Filesystem;

/**
 * INBOX selection (UID cursor, first scan, upgrade, UIDVALIDITY change,
 * full rescan), cursor advance on failures, per-mailbox lock and the
 * EntityManager reset after a failed flush.
 */
class ImapScanServiceTest extends TestCase
{
    private $tmp;
    /** @var array<int, string> uid => Message-ID */
    private $inbox = [];
    private $validity = 777;
    private $uidNext = null;
    /** SEARCH ALL answers with no UIDs (FETCH still works) */
    private $searchBroken = false;
    /** @var string[] search criteria / sequences requested from the server */
    private $requests = [];
    /** @var int[] UIDs that reached the end of the pipeline */
    private $processed = [];
    /** @var int[] UIDs whose processing throws */
    private $failing = [];
    /** @var MessageEvent[] events that reached the end of the pipeline */
    private $events = [];

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/antispam-scan-' . bin2hex(random_bytes(4));
        $this->inbox = [];
        $this->requests = [];
        $this->processed = [];
        $this->failing = [];
        $this->validity = 777;
        $this->uidNext = null;
        $this->searchBroken = false;
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->tmp);
    }

    private function messages()
    {
        return new MessageService($this->tmp . '/checked');
    }

    private function service(MessageService $ms, ?ManagerRegistry $doctrine = null, ?ConfigService $config = null)
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener('antispam.check.message', [new CheckIfIsAlreadyChecked($ms), 'check'], 100000);
        $dispatcher->addListener('antispam.check.message', function (MessageEvent $e) {
            $uid = $e->getMessage()->getNumber();
            if (in_array($uid, $this->failing, true)) {
                throw new \RuntimeException('boom');
            }
            $this->processed[] = $uid;
            $this->events[] = $e;
        }, 0);
        $dispatcher->addListener('antispam.check.message', [new SetAsChecked($ms), 'set'], -99999);

        return new ImapScanService(
            $dispatcher,
            $this->createMock(ConnectionService::class),
            $config ?? $this->createMock(ConfigService::class),
            $this->createMock(CryptoService::class),
            $ms,
            $doctrine,
            $this->tmp . '/locks'
        );
    }

    private function connection()
    {
        $resource = $this->createMock(ImapResourceInterface::class);
        $mailbox = $this->createMock(MailboxInterface::class);
        $mailbox->method('getStatus')->willReturnCallback(function () {
            $s = new \stdClass();
            $s->uidvalidity = $this->validity;
            $s->messages = count($this->inbox);
            $s->uidnext = $this->uidNext ?? ($this->inbox ? max(array_keys($this->inbox)) + 1 : 1);
            return $s;
        });
        $mailbox->method('getMessages')->willReturnCallback(function (?ConditionInterface $search = null) use ($resource) {
            $this->requests[] = $search ? $search->toString() : 'ALL';
            return new MessageIterator($resource, $this->searchBroken ? [] : array_keys($this->inbox));
        });
        $mailbox->method('getMessageSequence')->willReturnCallback(function ($seq) use ($resource) {
            $this->requests[] = 'UID ' . $seq;
            [$from, $to] = array_pad(explode(':', $seq), 2, '*');
            $from = (int)$from;
            $to = $to === '*' ? PHP_INT_MAX : (int)$to;
            $uids = array_values(array_filter(array_keys($this->inbox), function ($u) use ($from, $to) { return $u >= $from && $u <= $to; }));
            if (!$uids && $this->inbox && $to === PHP_INT_MAX) {
                $uids = [max(array_keys($this->inbox))]; // "n:*" returns the newest message
            }
            return new MessageIterator($resource, $uids);
        });
        $mailbox->method('getMessage')->willReturnCallback(function ($uid) {
            $m = $this->createMock(MessageInterface::class);
            $m->method('getNumber')->willReturn($uid);
            $m->method('getId')->willReturn($this->inbox[$uid] ?? null);
            $m->method('getRawHeaders')->willReturn('X-Uid: ' . $uid);
            return $m;
        });

        $connection = $this->createMock(ConnectionInterface::class);
        $connection->method('getMailbox')->willReturn($mailbox);
        return $connection;
    }

    private function fill($from, $to)
    {
        for ($uid = $from; $uid <= $to; $uid++) {
            $this->inbox[$uid] = '<m' . $uid . '@x>';
        }
    }

    public function testFirstScanReadsWholeInboxAndStoresCursor()
    {
        $this->fill(1, 5);
        $scan = $this->service($this->messages());

        $stats = $scan->scan($this->connection(), 'box@firma.pl', false, true, null, null, $cursor);

        $this->assertSame(['ALL'], $this->requests);
        $this->assertSame([1, 2, 3, 4, 5], $this->processed);
        $this->assertSame(5, $stats['checked']);
        $this->assertSame(777, $cursor['uidvalidity']);
        $this->assertSame(5, $cursor['last_uid']);
    }

    public function testIncrementalScanFetchesOnlyNewUids()
    {
        $this->fill(1, 8);
        $scan = $this->service($this->messages());

        $stats = $scan->scan($this->connection(), 'box@firma.pl', false, false, ['uidvalidity' => 777, 'last_uid' => 5], null, $cursor);

        $this->assertSame(['UID 6:*'], $this->requests);
        $this->assertSame([6, 7, 8], $this->processed);
        $this->assertSame(3, $stats['checked']);
        $this->assertSame(8, $stats['total'], 'total = INBOX size');
        $this->assertSame(8, $cursor['last_uid']);
    }

    public function testNothingNewSkipsTheFetch()
    {
        $this->fill(1, 5);
        $scan = $this->service($this->messages());

        $scan->scan($this->connection(), 'box@firma.pl', false, false, ['uidvalidity' => 777, 'last_uid' => 5], null, $cursor);

        $this->assertSame([], $this->requests);
        $this->assertSame(5, $cursor['last_uid']);
    }

    public function testSequenceAnswerBelowCursorIsIgnored()
    {
        // UIDs 5 and 6 arrived and were deleted again: "5:*" answers with UID 4.
        $this->fill(1, 4);
        $this->uidNext = 7;
        $scan = $this->service($this->messages());

        $scan->scan($this->connection(), 'box@firma.pl', false, false, ['uidvalidity' => 777, 'last_uid' => 4], null, $cursor);

        $this->assertSame(['UID 5:*'], $this->requests);
        $this->assertSame([], $this->processed);
        $this->assertSame(4, $cursor['last_uid']);
    }

    public function testUpgradeWithoutCursorOnlyLooksAtRecentMail()
    {
        $this->fill(1, 5);
        $scan = $this->service($this->messages());

        $scan->scan($this->connection(), 'box@firma.pl', false, false, null, new \DateTimeImmutable('2026-10-27'), $cursor);

        $this->assertSame(['SINCE "27-Oct-2026"'], $this->requests);
        $this->assertSame(5, $cursor['last_uid']);
    }

    public function testUidValidityChangeFallsBackToRecentMail()
    {
        $this->fill(1, 3);
        $this->validity = 999;
        $scan = $this->service($this->messages());

        $scan->scan($this->connection(), 'box@firma.pl', false, false, ['uidvalidity' => 777, 'last_uid' => 3000], new \DateTimeImmutable('2026-10-01'), $cursor);

        $this->assertSame(['SINCE "1-Oct-2026"'], $this->requests);
        $this->assertSame(['uidvalidity' => 999, 'last_uid' => 3], array_intersect_key($cursor, ['uidvalidity' => 1, 'last_uid' => 1]));
    }

    public function testFullRescanCursorReadsWholeInbox()
    {
        $this->fill(1, 3);
        $scan = $this->service($this->messages());

        $scan->scan($this->connection(), 'box@firma.pl', false, false, ImapScanService::fullRescanCursor(), new \DateTimeImmutable('-1 day'), $cursor);

        $this->assertSame(['ALL'], $this->requests);
        $this->assertSame([1, 2, 3], $this->processed);
    }

    public function testFailedMessageKeepsIncrementalCursorBelowIt()
    {
        $this->fill(1, 10);
        $this->failing = [8];
        $ms = $this->messages();
        $scan = $this->service($ms);

        $stats = $scan->scan($this->connection(), 'box@firma.pl', false, false, ['uidvalidity' => 777, 'last_uid' => 6], null, $cursor);
        $this->assertSame([7, 9, 10], $this->processed);
        $this->assertCount(1, $stats['errors']);
        $this->assertSame(7, $cursor['last_uid']);

        // Next run retries 8; 9 and 10 are skipped by their markers.
        $this->failing = [];
        $this->processed = [];
        $stats = $scan->scan($this->connection(), 'box@firma.pl', false, false, $cursor, null, $cursor);
        $this->assertSame([8], $this->processed);
        $this->assertSame(2, $stats['skipped']);
        $this->assertSame(10, $cursor['last_uid']);
    }

    public function testFailureInSincePassDoesNotPinTheCursor()
    {
        $this->fill(1, 4);
        $this->failing = [2];
        $scan = $this->service($this->messages());

        $scan->scan($this->connection(), 'box@firma.pl', false, false, null, new \DateTimeImmutable('-1 day'), $cursor);

        // Mail above a failure in a "since" pass may be old: never pick it up later.
        $this->assertSame(4, $cursor['last_uid']);
    }

    public function testNoUidValidityMeansNoCursor()
    {
        $this->fill(1, 2);
        $this->validity = 0;
        $scan = $this->service($this->messages());

        $scan->scan($this->connection(), 'box@firma.pl', false, false, null, new \DateTimeImmutable('-1 day'), $cursor);
        $this->assertNull($cursor);
    }

    public function testScanAccountUsesStoredCursorAndSavesTheNewOne()
    {
        $this->fill(1, 9);
        $connection = $this->connection();
        $account = (new Account())->setEmail('box@firma.pl')->setImapCursor(['uidvalidity' => 777, 'last_uid' => 7]);
        $account->markScanned(['total' => 0]);

        $scan = $this->getMockBuilder(ImapScanService::class)
            ->setConstructorArgs([$this->dispatcherWithCounter(), $this->createMock(ConnectionService::class), $this->createMock(ConfigService::class),
                $this->createMock(CryptoService::class), $this->messages(), null, $this->tmp . '/locks'])
            ->onlyMethods(['connect'])
            ->getMock();
        $scan->method('connect')->willReturn($connection);

        $scan->scanAccount($account);

        $this->assertSame(['UID 8:*'], $this->requests);
        $this->assertSame(['uidvalidity' => 777, 'last_uid' => 9], $account->getImapCursor());
    }

    public function testAccountScannedBeforeWithoutCursorUsesLastScanWindow()
    {
        $this->fill(1, 3);
        $account = (new Account())->setEmail('box@firma.pl');
        $account->setLastScanAt(new \DateTime('2026-10-20 10:00'));

        $scan = $this->getMockBuilder(ImapScanService::class)
            ->setConstructorArgs([$this->dispatcherWithCounter(), $this->createMock(ConnectionService::class), $this->createMock(ConfigService::class),
                $this->createMock(CryptoService::class), $this->messages(), null, $this->tmp . '/locks'])
            ->onlyMethods(['connect'])
            ->getMock();
        $scan->method('connect')->willReturn($this->connection());

        $scan->scanAccount($account);

        $this->assertSame(['SINCE "19-Oct-2026"'], $this->requests);
        $this->assertSame(3, $account->getImapLastUid());
    }

    public function testSecondConcurrentScanOfTheSameMailboxIsRefused()
    {
        $account = (new Account())->setEmail('box@firma.pl');
        mkdir($this->tmp . '/locks', 0777, true);
        $held = fopen($this->tmp . '/locks/imap-scan-' . sha1('account-box@firma.pl-') . '.lock', 'c');
        $this->assertTrue(flock($held, LOCK_EX | LOCK_NB));

        $scan = $this->getMockBuilder(ImapScanService::class)
            ->setConstructorArgs([$this->dispatcherWithCounter(), $this->createMock(ConnectionService::class), $this->createMock(ConfigService::class),
                $this->createMock(CryptoService::class), $this->messages(), null, $this->tmp . '/locks'])
            ->onlyMethods(['connect'])
            ->getMock();
        $scan->expects($this->never())->method('connect');

        try {
            $scan->scanAccount($account);
            $this->fail('expected the lock to refuse the scan');
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('już trwa', $e->getMessage());
        } finally {
            flock($held, LOCK_UN);
            fclose($held);
        }
    }

    public function testClosedEntityManagerIsResetSoTheRunContinues()
    {
        $this->fill(1, 3);
        $open = true;
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('isOpen')->willReturnCallback(function () use (&$open) { return $open; });
        $doctrine = $this->createMock(ManagerRegistry::class);
        $doctrine->method('getManager')->willReturn($em);
        $doctrine->expects($this->once())->method('resetManager')->willReturnCallback(function () use (&$open, $em) {
            $open = true;
            return $em;
        });

        $this->failing = [2];
        $scan = $this->service($this->messages(), $doctrine);
        // UID 2 fails *and* leaves the EntityManager closed (failed flush).
        $dispatcher = new \ReflectionProperty(ImapScanService::class, 'dispatcher');
        $dispatcher->getValue($scan)->addListener('antispam.check.message', function (MessageEvent $e) use (&$open) {
            if ($e->getMessage()->getNumber() === 2) {
                $open = false;
            }
        }, 10);

        $stats = $scan->scan($this->connection(), 'box@firma.pl', false, false, null, null, $cursor);

        $this->assertSame([1, 3], $this->processed);
        $this->assertCount(2, $stats['errors']);
    }

    public function testLegacyCursorRoundTrip()
    {
        $this->assertNull(ImapScanService::decodeCursor(null));
        $this->assertNull(ImapScanService::decodeCursor('junk'));
        $c = ImapScanService::decodeCursor(ImapScanService::encodeCursor(['uidvalidity' => 5, 'last_uid' => 42, 'scanned_at' => 1700000000]));
        $this->assertSame(['uidvalidity' => 5, 'last_uid' => 42, 'scanned_at' => 1700000000], $c);
    }

    private function dispatcherWithCounter()
    {
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener('antispam.check.message', function (MessageEvent $e) {
            $this->processed[] = $e->getMessage()->getNumber();
        });
        return $dispatcher;
    }

    // ---- batches (background scan jobs, scan-all time budget) ---------------

    public function testFirstScanInBatchesContinuesFromTheCursorUntilDone()
    {
        $this->fill(1, 25);
        $scan = $this->service($this->messages());

        $stats = $scan->scan($this->connection(), 'box@firma.pl', false, true, null, null, $cursor, 10);
        $this->assertSame(range(1, 10), $this->processed);
        $this->assertSame(15, $stats['remaining']);
        $this->assertSame(10, $cursor['last_uid'], 'the cursor points at the last processed message');

        $stats = $scan->scan($this->connection(), 'box@firma.pl', false, true, $cursor, null, $cursor, 10);
        $this->assertSame(['ALL', 'UID 11:*'], $this->requests, 'the second batch reads only what is above the cursor');
        $this->assertSame(5, $stats['remaining']);

        $stats = $scan->scan($this->connection(), 'box@firma.pl', false, true, $cursor, null, $cursor, 10);
        $this->assertSame(0, $stats['remaining']);
        $this->assertSame(range(1, 25), $this->processed, 'every message exactly once');
        $this->assertSame(25, $cursor['last_uid']);
    }

    public function testBatchStoppedByTheDeadlineStillProcessesOneMessage()
    {
        $this->fill(1, 3);
        $stats = $this->service($this->messages())->scan($this->connection(), 'box@firma.pl', false, true, null, null, $cursor, null, microtime(true) - 1);
        $this->assertSame([1], $this->processed, 'an expired deadline cannot stall the scan forever');
        $this->assertSame(2, $stats['remaining']);
        $this->assertSame(1, $cursor['last_uid']);
    }

    public function testFailedMessageInABatchIsRetriedByTheNextBatch()
    {
        $this->fill(1, 6);
        $this->failing = [2];
        $scan = $this->service($this->messages());
        $scan->scan($this->connection(), 'box@firma.pl', false, true, null, null, $cursor, 4);
        $this->assertSame(1, $cursor['last_uid'], 'the cursor stays below the failed message');

        $this->failing = [];
        $scan->scan($this->connection(), 'box@firma.pl', false, true, $cursor, null, $cursor, 10);
        $this->assertSame([1, 3, 4, 2, 5, 6], $this->processed, 'the failed one is retried, done ones are skipped by their markers');
        $this->assertSame(6, $cursor['last_uid']);
    }

    public function testSincePassIsNeverCutShort()
    {
        $this->fill(1, 5);
        $stats = $this->service($this->messages())->scan($this->connection(), 'box@firma.pl', false, false, null, new \DateTimeImmutable('-1 day'), $cursor, 2);
        $this->assertSame(0, $stats['remaining'], 'a "since" pass must not leave a cursor below older mail');
        $this->assertSame(range(1, 5), $this->processed);
    }

    public function testScanAccountReportsInitialAndThrowsScanLockedWhenBusy()
    {
        $this->fill(1, 4);
        $account = (new Account())->setEmail('box@firma.pl');
        $scan = $this->getMockBuilder(ImapScanService::class)
            ->setConstructorArgs([$this->dispatcherWithCounter(), $this->createMock(ConnectionService::class), $this->createMock(ConfigService::class),
                $this->createMock(CryptoService::class), $this->messages(), null, $this->tmp . '/locks'])
            ->onlyMethods(['connect'])
            ->getMock();
        $scan->method('connect')->willReturn($this->connection());

        $stats = $scan->scanAccount($account, 3);
        $this->assertTrue($stats['initial']);
        $this->assertSame(1, $stats['remaining']);
        $this->assertSame(3, $account->getImapLastUid());

        $held = fopen($this->tmp . '/locks/imap-scan-' . sha1(ImapScanService::accountLockName($account)) . '.lock', 'c'); // dir made by the first scan
        flock($held, LOCK_EX | LOCK_NB);
        try {
            $this->expectException(\AntispamBundle\Services\ScanLockedException::class);
            $scan->scanAccount($account);
        } finally {
            flock($held, LOCK_UN);
            fclose($held);
        }
    }

    public function testRescanIgnoresMarkersMovesInsteadOfDeletingAndStaysOutOfStats()
    {
        $this->fill(1, 5);
        $ms = $this->messages();
        $scan = $this->service($ms);
        $scan->scan($this->connection(), 'box@firma.pl', true, false, null, null, $cursor);
        $this->assertSame([1, 2, 3, 4, 5], $this->processed);
        $this->processed = [];
        $this->events = [];

        $stats = $scan->rescan($this->connection(), 'box@firma.pl');
        $this->assertSame([1, 2, 3, 4, 5], $this->processed, 'every message again, markers ignored');
        $this->assertSame([5, 0, 0], [$stats['checked'], $stats['skipped'], $stats['remaining']]);
        $this->assertNull($stats['cursor'], 'done');
        foreach ($this->events as $e) {
            $this->assertTrue($e->isRescan());
            $this->assertTrue($e->isInitialScan(), 'kept out of the statistics and rule counters');
            $this->assertFalse($e->getDeleteSpam(), 'spam is moved, never deleted');
        }

        // A full pass of the normal scan afterwards still skips everything (markers set again).
        $this->processed = [];
        $scan->scan($this->connection(), 'box@firma.pl', true, false, ['uidvalidity' => 0, 'last_uid' => 0], null, $cursor);
        $this->assertSame([], $this->processed);
    }

    public function testRescanRunsInBatchesUpToTheMessagesThatExistedAtTheStart()
    {
        $this->fill(1, 5);
        $scan = $this->service($this->messages());

        $stats = $scan->rescan($this->connection(), 'box@firma.pl', null, 2);
        $this->assertSame([1, 2], $this->processed);
        $this->assertSame(3, $stats['remaining']);
        $this->assertSame(['uidvalidity' => 777, 'last_uid' => 2, 'until_uid' => 5, 'left' => 3], $stats['cursor']);

        $this->fill(6, 6); // arrives during the rescan: the regular scan's job
        $stats = $scan->rescan($this->connection(), 'box@firma.pl', $stats['cursor'], 2);
        $this->assertSame([1, 2, 3, 4], $this->processed);
        $this->assertSame(1, $stats['remaining']);

        $stats = $scan->rescan($this->connection(), 'box@firma.pl', $stats['cursor'], 2);
        $this->assertSame([1, 2, 3, 4, 5], $this->processed);
        $this->assertSame([0, null], [$stats['remaining'], $stats['cursor']]);
    }

    public function testRescanFallsBackToFetchWhenSearchAllReturnsNothing()
    {
        // Interia, 30 390 messages: SEARCH ALL answered with no UIDs, the job said "finished, checked 0".
        $this->fill(1, 3);
        $this->searchBroken = true;
        $stats = $this->service($this->messages())->rescan($this->connection(), 'box@firma.pl');

        $this->assertSame([1, 2, 3], $this->processed);
        $this->assertContains('UID 1:*', $this->requests);
        $this->assertSame(3, $stats['checked']);
    }

    public function testRescanIgnoresAStatusUidNextBelowTheRealUids()
    {
        $this->fill(100, 102);
        $this->uidNext = 5; // broken STATUS: would have filtered out every message
        $stats = $this->service($this->messages())->rescan($this->connection(), 'box@firma.pl', null, 2);

        $this->assertSame([100, 101], $this->processed);
        $this->assertSame(['uidvalidity' => 777, 'last_uid' => 101, 'until_uid' => 102, 'left' => 1], $stats['cursor']);
    }

    public function testRescanThatCannotListAFullInboxFails()
    {
        $this->fill(1, 3);
        $this->searchBroken = true;
        $connection = $this->connection();
        $mailbox = $connection->getMailbox('INBOX');
        // FETCH 1:* fails too.
        $broken = $this->createMock(ConnectionInterface::class);
        $inbox = $this->createMock(MailboxInterface::class);
        $inbox->method('getStatus')->willReturnCallback(fn () => $mailbox->getStatus());
        $inbox->method('getMessages')->willReturn(new MessageIterator($this->createMock(ImapResourceInterface::class), []));
        $inbox->method('getMessageSequence')->willThrowException(new InvalidSearchCriteriaException('x'));
        $broken->method('getMailbox')->willReturn($inbox);

        $this->expectExceptionMessage('STATUS zgłasza 3 wiadomości w INBOX');
        $this->service($this->messages())->rescan($broken, 'box@firma.pl');
    }

    public function testRescanContinuationListsOnlyTheNextChunkOfUids()
    {
        // 30 000-message INBOX: never "everything above the cursor" (n:*) in a later batch.
        $this->fill(1, 1200);
        $scan = $this->service($this->messages());
        $stats = $scan->rescan($this->connection(), 'box@firma.pl', null, 10);
        $this->assertSame(1190, $stats['cursor']['left']);
        $this->requests = [];

        $stats = $scan->rescan($this->connection(), 'box@firma.pl', $stats['cursor'], 10);
        $this->assertSame(['UID 11:510'], $this->requests);
        $this->assertSame(range(1, 20), $this->processed);
        $this->assertSame([1180, 20], [$stats['remaining'], $stats['cursor']['last_uid']]);
        $this->assertSame(10, $stats['timing']['messages']);
    }

    public function testRescanWidensTheListingWindowOverUidGaps()
    {
        $this->fill(1, 1);
        $this->fill(100000, 100001);
        $scan = $this->service($this->messages());
        $stats = $scan->rescan($this->connection(), 'box@firma.pl', null, 1);
        $this->requests = [];

        $stats = $scan->rescan($this->connection(), 'box@firma.pl', $stats['cursor']);
        $this->assertSame([1, 100000, 100001], $this->processed);
        $this->assertLessThan(10, count($this->requests), 'a few round trips, not 200 empty chunks');
        $this->assertNull($stats['cursor']);
    }

    public function testRescanWithoutStatusFailsTheBatchAndKeepsTheCursor()
    {
        // A transient STATUS failure used to restart from UID 1 in one unlimited pass.
        $this->fill(1, 5);
        $this->validity = 0;
        try {
            $this->service($this->messages())->rescan($this->connection(), 'box@firma.pl', ['uidvalidity' => 777, 'last_uid' => 3, 'until_uid' => 5, 'left' => 2], 10);
            $this->fail('expected an exception');
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('UIDVALIDITY', $e->getMessage());
        }
        $this->assertSame([], $this->processed);
    }

    public function testRescanCursorWithoutLeftIsEstimated()
    {
        // Rescans queued before this version carry no 'left'.
        $this->fill(1, 10);
        $stats = $this->service($this->messages())->rescan($this->connection(), 'box@firma.pl', ['uidvalidity' => 777, 'last_uid' => 4, 'until_uid' => 10], 2);
        $this->assertSame([5, 6], $this->processed);
        $this->assertSame(4, $stats['remaining']);
    }

    public function testRescanStopsAtTheNextMessageWhenTheJobIsCancelled()
    {
        // "Anuluj" stops a running batch within seconds, keeping the cursor (not after 2 minutes).
        $this->fill(1, 10);
        $cancel = new class extends JobCancellation {
            public int $asked = 0;
            public function isRequested(): bool { return ++$this->asked >= 3; }
        };
        $base = $this->service($this->messages());
        $scan = new ImapScanService((fn () => $this->dispatcher)->call($base), $this->createMock(ConnectionService::class), $this->createMock(ConfigService::class),
            $this->createMock(CryptoService::class), $this->messages(), null, $this->tmp . '/locks', cancellation: $cancel);

        $stats = $scan->rescan($this->connection(), 'box@firma.pl', null, null, microtime(true) + 600);
        $this->assertSame([1, 2, 3], $this->processed);
        $this->assertSame(['last_uid' => 3, 'left' => 7], ['last_uid' => $stats['cursor']['last_uid'], 'left' => $stats['cursor']['left']]);
    }

    public function testRescanSkipsAFailingMessageAndStartsOverAfterUidValidityChange()
    {
        $this->fill(1, 4);
        $this->failing = [2];
        $scan = $this->service($this->messages());

        $stats = $scan->rescan($this->connection(), 'box@firma.pl');
        $this->assertSame([1, 3, 4], $this->processed, 'a broken message does not stall the rescan');
        $this->assertCount(1, $stats['errors']);
        $this->assertNull($stats['cursor']);

        $this->failing = [];
        $this->processed = [];
        $this->validity = 888;
        $stats = $scan->rescan($this->connection(), 'box@firma.pl', ['uidvalidity' => 777, 'last_uid' => 3, 'until_uid' => 4]);
        $this->assertSame([1, 2, 3, 4], $this->processed);
        $this->assertStringContainsString('UIDVALIDITY', $stats['errors'][0]);
    }
}
