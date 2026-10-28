<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Repository\SpamScoreLogRepository;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\SpamFolderService;
use AntispamBundle\Services\SshService;
use AntispamBundle\Tests\Security\MailboxAccessTest;
use AntispamBundle\Tests\Support\InMemoryRepository;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\ImapResourceInterface;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\Message\EmailAddress;
use Ddeboer\Imap\MessageInterface;
use Ddeboer\Imap\MessageIterator;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * SPAM folder listing / release for the user area: IMAP accounts (mocked
 * connection) and SSH accounts (agent spam-list / spam-release through a
 * mocked SshService).
 */
class SpamFolderServiceTest extends TestCase
{
    /** @var QuarantineService&MockObject */
    private $quarantine;
    /** @var SshService&MockObject */
    private $ssh;
    /** @var MessageService&MockObject */
    private $messages;
    /** @var ConnectionInterface&MockObject */
    private $connection;
    /** @var MailboxInterface&MockObject */
    private $spamFolder;
    /** @var MailboxInterface&MockObject */
    private $inboxFolder;
    private array $logs = [];

    private function service(): SpamFolderService
    {
        $accounts = new InMemoryRepository([
            MailboxAccessTest::account(5, 'jan@firma.pl'),
            MailboxAccessTest::account(7, 'jan@ssh.pl', Account::CONNECTION_SSH),
        ]);
        $logRepo = $this->createMock(SpamScoreLogRepository::class);
        $logRepo->method('findDecisionsBySenders')->willReturnCallback(function ($account, $senders, $decision) {
            $this->assertSame('jan@firma.pl', $account);
            $this->assertSame(SpamScoreLog::DECISION_SPAM, $decision);
            return $this->logs;
        });
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturnCallback(fn($class) => $class === SpamScoreLog::class ? $logRepo : $accounts);

        $this->quarantine = $this->createMock(QuarantineService::class);
        $this->quarantine->method('getMailbox')->willReturnCallback(fn($key) => match ($key) {
            'imap-5' => ['key' => 'imap-5', 'label' => 'Jan', 'account_email' => 'jan@firma.pl', 'recipient' => 'jan@firma.pl'],
            'ssh-7' => ['key' => 'ssh-7', 'label' => 'Jan SSH', 'account_email' => 'jan@ssh.pl', 'recipient' => 'jan@ssh.pl'],
            default => null,
        });
        $this->ssh = $this->createMock(SshService::class);
        $this->messages = $this->createMock(MessageService::class);

        $this->spamFolder = $this->createMock(MailboxInterface::class);
        $this->inboxFolder = $this->createMock(MailboxInterface::class);
        $this->connection = $this->createMock(ConnectionInterface::class);
        $this->connection->method('hasMailbox')->willReturnCallback(fn($name) => $name === 'SPAM');
        $this->connection->method('getMailbox')->willReturnCallback(fn($name) => $name === 'SPAM' ? $this->spamFolder : $this->inboxFolder);
        $imapScan = $this->createMock(ImapScanService::class);
        $imapScan->method('connect')->willReturn($this->connection);
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getSpamFolderName')->willReturn('SPAM');

        return new SpamFolderService($em, $this->quarantine, $this->ssh, $imapScan, $this->createMock(ConnectionService::class), $inbox, $this->messages);
    }

    private function message(int $uid, string $from, string $subject): MessageInterface
    {
        $msg = $this->createMock(MessageInterface::class);
        [$local, $host] = explode('@', $from);
        $msg->method('getFrom')->willReturn(new EmailAddress($local, $host, 'Nadawca ' . $uid));
        $msg->method('getSubject')->willReturn($subject);
        $msg->method('getDate')->willReturn(new \DateTimeImmutable('2026-10-0' . $uid));
        $msg->method('getNumber')->willReturn($uid);
        return $msg;
    }

    private function uidValidity(int $value): void
    {
        $this->spamFolder->method('getStatus')->willReturn((object)['uidvalidity' => $value]);
    }

    public function testImapListsNewestFirstWithScoresFromTheLog()
    {
        $service = $this->service();
        $this->uidValidity(42);
        $msgs = [1 => $this->message(1, 'old@x.pl', 'stary'), 3 => $this->message(3, 'promo@sklep.pl', 'Promocja'), 2 => $this->message(2, 'b@x.pl', 'b')];
        $this->spamFolder->method('getMessages')->willReturn(new MessageIterator($this->createMock(ImapResourceInterface::class), [1, 2, 3]));
        $this->spamFolder->method('getMessage')->willReturnCallback(fn($uid) => $msgs[$uid]);
        $log = (new SpamScoreLog())->setSender('promo@sklep.pl')->setSubject('Promocja')->setScore(14)->setDecision(SpamScoreLog::DECISION_SPAM)
            ->setReasons(json_encode([['rule' => 'email_blacklist:promo@sklep.pl', 'score' => 14]]));
        $this->logs = [$log];

        $list = $service->listItems('imap-5', 2);

        $this->assertSame(3, $list['total']);
        $this->assertSame(['3', '2'], array_column($list['items'], 'id'));
        $this->assertSame(14, $list['items'][0]['score']);
        $this->assertSame('email_blacklist:promo@sklep.pl', $list['items'][0]['reasons'][0]['rule']);
        $this->assertSame(QuarantineService::REASON_SCORE_UNKNOWN, $list['items'][1]['reasons'][0]['rule'], 'no log row = unknown (high risk)');
        $this->assertSame(42, $list['items'][0]['uidvalidity']);
    }

    public function testImapWithoutSpamFolderIsEmpty()
    {
        $service = $this->service();
        $this->connection = $this->createMock(ConnectionInterface::class);
        $this->connection->method('hasMailbox')->willReturn(false);
        $imap = $this->createMock(ImapScanService::class);
        $imap->method('connect')->willReturn($this->connection);
        (new \ReflectionProperty($service, 'imapScan'))->setValue($service, $imap);

        $this->assertSame(['items' => [], 'total' => 0], $service->listItems('imap-5'));
    }

    public function testImapReleaseMarksCheckedMovesAndWhitelists()
    {
        $service = $this->service();
        $this->uidValidity(42);
        $msg = $this->message(3, 'Promo@Sklep.pl', 'Promocja');
        $this->spamFolder->method('getMessage')->with(3)->willReturn($msg);
        $this->messages->expects($this->once())->method('setAsChecked')->with($msg, 'jan@firma.pl');
        $msg->expects($this->once())->method('move')->with($this->inboxFolder);
        $this->connection->expects($this->once())->method('expunge');
        $this->quarantine->expects($this->once())->method('whitelistSender')->with('jan@firma.pl', 'promo@sklep.pl');

        $res = $service->release('imap-5', '3', true, 42);
        $this->assertTrue($res['success']);
        $this->assertTrue($res['whitelisted']);
        $this->assertSame('promo@sklep.pl', $res['sender']);
    }

    public function testImapReleaseRefusesAStaleUidValidityAndBadIds()
    {
        $service = $this->service();
        $this->uidValidity(43);
        $this->spamFolder->expects($this->never())->method('getMessage');
        $this->messages->expects($this->never())->method('setAsChecked');

        $this->assertFalse($service->release('imap-5', '3', false, 42)['success']);
        $this->assertFalse($service->release('imap-5', '3; DROP', false, null)['success']);
        $this->assertFalse($service->release('imap-99', '3')['success'], 'unknown mailbox');
    }

    public function testSshListUsesTheAgent()
    {
        $service = $this->service();
        $this->ssh->expects($this->once())->method('spamList')->with($this->callback(fn($a) => $a->getId() === 7), 100)
            ->willReturn(['success' => true, 'total' => 120, 'items' => [
                ['id' => '1.M1.host', 'from' => 'a@spam.pl', 'subject' => 'x', 'date' => '2026-10-01T10:00:00+00:00', 'score' => 15, 'reasons' => [['rule' => 'blacklist:spam.pl', 'score' => 15]]],
                ['id' => '2.M2.host', 'from' => 'b@spam.pl', 'subject' => 'y', 'date' => null, 'score' => null, 'reasons' => []],
            ]]);

        $list = $service->listItems('ssh-7');
        $this->assertSame(120, $list['total']);
        $this->assertSame('1.M1.host', $list['items'][0]['id']);
        $this->assertSame(15, $list['items'][0]['score']);
        $this->assertSame(QuarantineService::REASON_SCORE_UNKNOWN, $list['items'][1]['reasons'][0]['rule']);
    }

    public function testSshListFailureThrowsForTheController()
    {
        $service = $this->service();
        $this->ssh->method('spamList')->willReturn(['success' => false, 'error' => 'Agent na serwerze nie obsługuje polecenia "spam-list"']);
        $this->expectException(\RuntimeException::class);
        $service->listItems('ssh-7');
    }

    public function testSshReleaseAndWhitelist()
    {
        $service = $this->service();
        $this->ssh->expects($this->once())->method('spamRelease')->with($this->anything(), '1.M1.host', true)
            ->willReturn(['success' => true, 'sender' => 'A@spam.pl', 'whitelisted' => true]);
        $this->quarantine->expects($this->once())->method('whitelistSender')->with('jan@ssh.pl', 'a@spam.pl');

        $res = $service->release('ssh-7', '1.M1.host', true);
        $this->assertTrue($res['success']);
        $this->assertStringContainsString('a@spam.pl', $res['message']);
    }

    public function testSshReleaseErrorsAreNotLeaked()
    {
        $service = $this->service();
        $this->ssh->method('spamRelease')->willReturnOnConsecutiveCalls(
            ['success' => false, 'error' => 'Message not found in the SPAM folder'],
            ['success' => false, 'error' => 'PHP Fatal error in /home/u/antispam-agent/antispam-agent.php'],
            ['success' => false, 'error' => 'Agent na serwerze nie obsługuje polecenia "spam-release" (starsza wersja)'],
        );
        $this->quarantine->expects($this->never())->method('whitelistSender');

        $this->assertSame(SpamFolderService::NOT_FOUND, $service->release('ssh-7', 'x', true)['message']);
        $this->assertStringNotContainsString('/home/u', $service->release('ssh-7', 'x')['message']);
        $this->assertStringContainsString('starszej wersji', $service->release('ssh-7', 'x')['message']);
    }
}
