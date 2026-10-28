<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Controller\SpamboxController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\Jobs\Handler\QuarantinePurgeHandler;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\QuarantineDigestService;
use AntispamBundle\Services\QuarantinePurge;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\SshService;
use AntispamBundle\Tests\Support\JobsDatabase;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\Message\EmailAddress;
use Ddeboer\Imap\MessageInterface;
use Ddeboer\Imap\MessageIteratorInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * "Usuń wszystkie wysokiego ryzyka" / "Usuń wszystko z kwarantanny":
 * QuarantineService::purge() (IMAP selection at run time with the same
 * high-risk rule as "Zawsze akceptuj", only the quarantine folder, SSH through
 * the agent) and the background job (dedupe, ownership re-check, audit).
 */
class QuarantinePurgeTest extends TestCase
{
    private JobsDatabase $db;
    private Account $imap;
    private Account $ssh;
    /** @var SshService&MockObject */
    private $sshService;
    /** @var ConnectionInterface&MockObject */
    private $conn;
    /** @var MailboxInterface&MockObject */
    private $folder;
    private string $quarantineFolder = 'QUARANTINE';
    /** @var string[] mailbox names opened on the IMAP connection */
    private array $opened = [];
    private int $expunges = 0;
    private array $audits = [];

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
        $this->imap = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP)->setImapHost('imap.firma.pl');
        $this->ssh = (new Account())->setName('Ola')->setEmail('ola@firma.pl')->setConnectionType(Account::CONNECTION_SSH)->setAgentDeployed(true);
        $this->db->em->persist($this->imap);
        $this->db->em->persist($this->ssh);
        $this->db->em->flush();

        $this->sshService = $this->createMock(SshService::class);
        $this->folder = $this->createMock(MailboxInterface::class);
        $this->conn = $this->createMock(ConnectionInterface::class);
        $this->conn->method('hasMailbox')->willReturn(true);
        $this->conn->method('getMailbox')->willReturnCallback(function (string $name) {
            $this->opened[] = $name;
            return $this->folder;
        });
        $this->conn->method('expunge')->willReturnCallback(function () {
            $this->expunges++;
            return true;
        });
    }

    private function service(): QuarantineService
    {
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getQuarantineFolderName')->willReturnCallback(fn() => $this->quarantineFolder);
        $inbox->method('getSpamFolderName')->willReturn('SPAM');
        $imapScan = $this->createMock(ImapScanService::class);
        $imapScan->method('connect')->willReturn($this->conn);
        return new QuarantineService($this->db->em, new ConfigService($this->db->em), $this->sshService,
            $this->createMock(ConnectionService::class), $inbox, $this->createMock(MessageService::class), $imapScan);
    }

    /** @param MessageInterface[] $messages */
    private function inFolder(array $messages): void
    {
        $this->folder->method('getMessages')->willReturn(new class($messages) extends \ArrayIterator implements MessageIteratorInterface {
            public function current(): MessageInterface { return parent::current(); }
        });
    }

    private function message(int $uid, string $from, string $subject, bool $expectDelete): MessageInterface
    {
        $m = $this->createMock(MessageInterface::class);
        [$box, $host] = explode('@', $from);
        $m->method('getFrom')->willReturn(new EmailAddress($box, $host));
        $m->method('getSubject')->willReturn($subject);
        $m->method('getNumber')->willReturn($uid);
        $m->expects($expectDelete ? $this->once() : $this->never())->method('delete');
        return $m;
    }

    private function scoreLog(string $account, string $sender, string $subject, array $reasons): void
    {
        $this->db->em->persist((new SpamScoreLog())->setAccountEmail($account)->setSender($sender)->setSubject($subject)
            ->setScore(7)->setDecision(SpamScoreLog::DECISION_QUARANTINE)->setReasons($reasons));
        $this->db->em->flush();
    }

    private function key(Account $a): string
    {
        return ($a->isSsh() ? 'ssh-' : 'imap-') . $a->getId();
    }

    public function testHighRiskModeDeletesOnlyWhatIsHighRiskNow()
    {
        $this->scoreLog('jan@firma.pl', 'ceo@evil.pl', 'Przelew', [['rule' => 'impersonation_vip:Jan', 'score' => 8]]);
        $this->scoreLog('jan@firma.pl', 'news@sklep.pl', 'Promocja', [['rule' => 'dkim_fail', 'score' => 4]]);
        $this->scoreLog('jan@firma.pl', 'x@att.pl', 'Faktura', [['rule' => 'attachment_double_extension', 'score' => 6]]);
        // Same sender + subject in ANOTHER mailbox with a harmless reason: must not make it "safe".
        $this->scoreLog('boss@firma.pl', 'who@unknown.pl', 'Hej', [['rule' => 'dkim_fail', 'score' => 4]]);

        $this->inFolder([
            $this->message(1, 'ceo@evil.pl', 'Przelew', true),
            $this->message(2, 'news@sklep.pl', 'Promocja', false),
            $this->message(3, 'x@att.pl', 'Faktura', true),
            $this->message(4, 'who@unknown.pl', 'Hej', false), // no own score row = score_unknown: kept (deletion never fails closed)
        ]);

        $r = $this->service()->purge($this->key($this->imap), QuarantineService::PURGE_HIGH_RISK);

        $this->assertSame(['total' => 4, 'deleted' => 2, 'skipped' => 2, 'failed' => 0, 'errors' => []], $r);
        $this->assertSame(['QUARANTINE'], array_values(array_unique($this->opened)), 'only the quarantine folder is opened');
        $this->assertSame(1, $this->expunges);
    }

    public function testPurgeableHighRiskIgnoresMissingScore()
    {
        $unknown = [['rule' => QuarantineService::REASON_SCORE_UNKNOWN, 'score' => 0]];
        $this->assertTrue(QuarantineDigestService::isHighRisk($unknown), '"Zawsze akceptuj" still fails closed');
        $this->assertFalse(QuarantineDigestService::isPurgeableHighRisk($unknown), 'bulk deletion does not');
        $this->assertTrue(QuarantineDigestService::isPurgeableHighRisk([['rule' => 'clamav:Eicar', 'score' => 100]]));
        $this->assertFalse(QuarantineDigestService::isPurgeableHighRisk([['rule' => 'dkim_fail', 'score' => 4]]));

        $counts = SpamboxController::purgeCounts([['reasons' => $unknown, 'high_risk' => true], ['reasons' => [['rule' => 'lookalike_domain']], 'high_risk' => true]], 100);
        $this->assertSame(1, $counts['high_risk_count'], 'the button count matches what the job deletes');
    }

    public function testAllModeDeletesEverythingAndCountsFailures()
    {
        $bad = $this->createMock(MessageInterface::class);
        $bad->method('getNumber')->willReturn(9);
        $bad->method('delete')->willThrowException(new \RuntimeException('gone'));
        $this->inFolder([$this->message(1, 'a@b.pl', 's', true), $this->message(2, 'c@d.pl', 't', true), $bad]);

        $r = $this->service()->purge($this->key($this->imap), QuarantineService::PURGE_ALL);

        $this->assertSame(3, $r['total']);
        $this->assertSame(2, $r['deleted']);
        $this->assertSame(1, $r['failed']);
        $this->assertStringContainsString('UID 9', $r['errors'][0]);
    }

    public function testRefusesToPurgeInboxOrSpamEvenIfMisconfigured()
    {
        $this->inFolder([$this->message(1, 'a@b.pl', 's', false)]);
        foreach (['INBOX', 'spam'] as $name) {
            $this->quarantineFolder = $name;
            try {
                $this->service()->purge($this->key($this->imap), QuarantineService::PURGE_ALL);
                $this->fail('purge of ' . $name . ' must be refused');
            } catch (\LogicException $e) {
                $this->assertStringContainsString('Refusing', $e->getMessage());
            }
        }
        $this->assertSame([], $this->opened);
    }

    public function testEmptyOrMissingQuarantineFolder()
    {
        $conn = $this->createMock(ConnectionInterface::class);
        $conn->method('hasMailbox')->willReturn(false);
        $conn->expects($this->never())->method('getMailbox');
        $this->conn = $conn;

        $r = $this->service()->purge($this->key($this->imap), QuarantineService::PURGE_ALL);
        $this->assertSame(0, $r['total'] + $r['deleted']);
    }

    public function testSshIsDelegatedToTheAgentAndAgentErrorsThrow()
    {
        $this->sshService->expects($this->exactly(2))->method('quarantinePurge')
            ->with($this->callback(fn($a) => $a->getId() === $this->ssh->getId()), 'high_risk')
            ->willReturnOnConsecutiveCalls(
                ['success' => true, 'total' => 5, 'deleted' => 2, 'skipped' => 3, 'failed' => 0],
                ['success' => false, 'error' => 'Agent na serwerze nie obsługuje polecenia "quarantine-purge"'],
            );
        $service = $this->service();

        $this->assertSame(['total' => 5, 'deleted' => 2, 'skipped' => 3, 'failed' => 0, 'errors' => []], $service->purge($this->key($this->ssh), 'high_risk'));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('nie obsługuje');
        $service->purge($this->key($this->ssh), 'high_risk');
    }

    public function testUnknownMailboxAndModeAreRejected()
    {
        $service = $this->service();
        try {
            $service->purge('imap-999', 'all');
            $this->fail('unknown mailbox');
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('nie jest już obsługiwana', $e->getMessage());
        }
        $this->expectException(\InvalidArgumentException::class);
        $service->purge($this->key($this->imap), 'everything');
    }

    /* ---------------------------------------------------------------- job */

    private function audit(): AuditLogger
    {
        $audit = $this->createMock(AuditLogger::class);
        $audit->method('log')->willReturnCallback(function (string $action, $targetType = null, $targetId = null, $label = null, $mailbox = null, array $details = [], $actor = null, $actorType = null) {
            $this->audits[] = compact('action', 'targetType', 'targetId', 'mailbox', 'details', 'actor', 'actorType');
        });
        $audit->method('currentActor')->willReturn(['admin', AuditLog::ACTOR_ENV_ADMIN, 'ROLE_ADMIN']);
        return $audit;
    }

    private function purger(): QuarantinePurge
    {
        return new QuarantinePurge($this->db->queue, $this->db->em, $this->audit());
    }

    private function runJobs(QuarantineService $service): void
    {
        $w = $this->db->worker([new QuarantinePurgeHandler($service, $this->db->em, new MailboxAccess())], $this->audit());
        $w->configure(0, 30);
        while ($w->runNext() !== null) {
        }
    }

    private function user(string $name, array $accounts): User
    {
        $u = (new User())->setUsername($name)->setPassword('x')->setRole(User::ROLE_USER)->setAccounts($accounts);
        $this->db->em->persist($u);
        $this->db->em->flush();
        return $u;
    }

    private function mailboxRow(Account $a): array
    {
        return ['key' => $this->key($a), 'label' => $a->getName() . ' (' . $a->getEmail() . ')', 'account_email' => $a->getEmail()];
    }

    public function testJobIsDedupedPerMailboxAndModeAndAudited()
    {
        $purger = $this->purger();
        $first = $purger->enqueue($this->mailboxRow($this->imap), 'all', QuarantinePurge::SOURCE_PANEL, 7);
        $again = $purger->enqueue($this->mailboxRow($this->imap), 'all', QuarantinePurge::SOURCE_PANEL, 7);
        $other = $purger->enqueue($this->mailboxRow($this->imap), 'high_risk', QuarantinePurge::SOURCE_PANEL, 2);

        $this->assertTrue($first->created);
        $this->assertFalse($again->created);
        $this->assertSame($first->id, $again->id);
        $this->assertNotSame($first->id, $other->id);
        $row = $this->db->row($first->id);
        $this->assertSame([BackgroundJob::TYPE_QUARANTINE_PURGE, 'jan@firma.pl', (string)$this->imap->getId(), 'quarantine.purge:imap-' . $this->imap->getId() . ':all'],
            [$row['type'], $row['mailbox'], (string)$row['account_id'], $row['active_key']]);
        $this->assertSame(['quarantine.purge_queued', 'quarantine.purge_queued'], array_column($this->audits, 'action'));
        $this->assertSame(['job' => $first->id, 'mode' => 'all', 'source' => 'panel', 'shown' => 7], $this->audits[0]['details']);
    }

    public function testJobRunsThePurgeAndStoresCounts()
    {
        $service = $this->createMock(QuarantineService::class);
        $service->expects($this->once())->method('purge')->with('ssh-' . $this->ssh->getId(), 'high_risk')
            ->willReturn(['total' => 4, 'deleted' => 3, 'skipped' => 1, 'failed' => 0, 'errors' => []]);

        $id = $this->purger()->enqueue($this->mailboxRow($this->ssh), 'high_risk', QuarantinePurge::SOURCE_PANEL, 3)->id;
        $this->audits = [];
        $this->runJobs($service);

        $row = $this->db->row($id);
        $this->assertSame('done', $row['status']);
        $result = json_decode($row['result'], true);
        $this->assertSame([3, 1, 0, 'high_risk', 3], [$result['deleted'], $result['skipped'], $result['failed'], $result['mode'], $result['shown']]);
        $this->assertNull($row['active_key'], 'dedupe key released at the end');
        $this->assertSame('quarantine.purge', $this->audits[0]['action']);
        $this->assertSame(['ok' => true, 'mode' => 'high_risk', 'source' => 'panel', 'total' => 4, 'deleted' => 3, 'skipped' => 1, 'failed' => 0, 'job' => $id], $this->audits[0]['details']);
    }

    public function testUserJobRunsOnlyWhileTheUserStillOwnsTheMailbox()
    {
        $jan = $this->user('jan', [$this->imap]);
        $service = $this->createMock(QuarantineService::class);
        $service->expects($this->once())->method('purge')->willReturn(['total' => 1, 'deleted' => 1, 'skipped' => 0, 'failed' => 0, 'errors' => []]);

        $ok = $this->purger()->enqueue($this->mailboxRow($this->imap), 'all', QuarantinePurge::SOURCE_MY, 1, $jan)->id;
        $this->assertSame(['jan', AuditLog::ACTOR_USER], [$this->db->row($ok)['requested_by'], $this->db->row($ok)['requested_by_type']]);
        $this->runJobs($service);
        $this->assertSame('done', $this->db->row($ok)['status']);

        // Access revoked (or a forged job for a foreign mailbox): the job fails, nothing is deleted.
        $jan = $this->db->em->getRepository(User::class)->findOneBy(['username' => 'jan']); // the worker cleared the EntityManager
        $jan->setAccounts([]);
        $this->db->em->flush();
        $denied = $this->purger()->enqueue($this->mailboxRow($this->imap), 'high_risk', QuarantinePurge::SOURCE_MY, 1, $jan)->id;
        $this->audits = [];
        $this->runJobs($service);
        $row = $this->db->row($denied);
        $this->assertSame('failed', $row['status']);
        $this->assertStringContainsString('Brak dostępu', $row['error']);
        $this->assertFalse($this->audits[0]['details']['ok']);
    }
}
