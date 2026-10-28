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
use AntispamBundle\Services\MessageService;
use Ddeboer\Imap\ConnectionInterface;
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
    /** @var string[] search criteria / sequences requested from the server */
    private $requests = [];
    /** @var int[] UIDs that reached the end of the pipeline */
    private $processed = [];
    /** @var int[] UIDs whose processing throws */
    private $failing = [];

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/antispam-scan-' . bin2hex(random_bytes(4));
        $this->inbox = [];
        $this->requests = [];
        $this->processed = [];
        $this->failing = [];
        $this->validity = 777;
        $this->uidNext = null;
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
            return new MessageIterator($resource, array_keys($this->inbox));
        });
        $mailbox->method('getMessageSequence')->willReturnCallback(function ($seq) use ($resource) {
            $this->requests[] = 'UID ' . $seq;
            $from = (int)explode(':', $seq)[0];
            $uids = array_values(array_filter(array_keys($this->inbox), function ($u) use ($from) { return $u >= $from; }));
            if (!$uids && $this->inbox) {
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
}
