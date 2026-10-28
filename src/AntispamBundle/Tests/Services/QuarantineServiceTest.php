<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\QuarantineDigestService;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\SshService;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\MailboxInterface;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;

/**
 * IMAP quarantine items get their score/reasons from the score log. The match
 * must stay inside the mailbox, survive long non-ASCII subjects, and fail
 * closed (no "always accept") when no row is found. Digest links carry the
 * folder UIDVALIDITY and are refused when it changed.
 */
class QuarantineServiceTest extends TestCase
{
    private EntityManager $em;
    private ConfigService $config;
    private ConnectionService $connection;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->config = new ConfigService($this->em);
        $this->connection = $this->createMock(ConnectionService::class);
    }

    private function service(): QuarantineService
    {
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getQuarantineFolderName')->willReturn('QUARANTINE');
        return new QuarantineService(
            $this->em,
            $this->config,
            $this->createMock(SshService::class),
            $this->connection,
            $inbox,
            $this->createMock(MessageService::class),
            $this->createMock(ImapScanService::class),
        );
    }

    private function log($account, $sender, $subject, array $reasons, $decision = SpamScoreLog::DECISION_QUARANTINE): SpamScoreLog
    {
        $log = (new SpamScoreLog())->setAccountEmail($account)->setSender($sender)->setSubject($subject)
            ->setScore(7)->setDecision($decision)->setReasons($reasons);
        $this->em->persist($log);
        $this->em->flush();
        return $log;
    }

    private static function item($from, $subject): array
    {
        return ['id' => '1', 'from' => $from, 'from_name' => '', 'subject' => $subject, 'date' => null, 'score' => null, 'reasons' => [], 'uidvalidity' => 1];
    }

    public function testScoresAreScopedToTheMailbox()
    {
        // Same sender + subject, but in another mailbox, with harmless reasons.
        $this->log('boss@firma.pl', 'x@evil.pl', 'Faktura', [['rule' => 'dkim_fail', 'score' => 4]]);

        $items = $this->service()->attachImapScores([self::item('x@evil.pl', 'Faktura')], 'jan@firma.pl');

        $this->assertNull($items[0]['score']);
        $this->assertSame(QuarantineService::REASON_SCORE_UNKNOWN, $items[0]['reasons'][0]['rule']);
        $this->assertTrue(QuarantineDigestService::isHighRisk($items[0]['reasons']), 'no own row -> no "always accept"');
    }

    public function testOwnRowIsUsedAndNewestWins()
    {
        $old = $this->log('jan@firma.pl', 'x@evil.pl', 'Faktura', [['rule' => 'impersonation_vip:Jan', 'score' => 8]]);
        $old->setScoredAt(new \DateTime('-2 days'));
        $this->em->flush();
        $this->log('jan@firma.pl', 'x@evil.pl', 'Faktura', [['rule' => 'dkim_fail', 'score' => 4]]);
        $this->log('jan@firma.pl', 'x@evil.pl', 'Faktura', [['rule' => 'x', 'score' => 1]], SpamScoreLog::DECISION_HAM);

        $items = $this->service()->attachImapScores([self::item('X@Evil.pl', 'Faktura'), self::item('y@ok.pl', 'Inne')], 'jan@firma.pl');

        $this->assertSame(7, $items[0]['score']);
        $this->assertSame('dkim_fail', $items[0]['reasons'][0]['rule']);
        $this->assertFalse(QuarantineDigestService::isHighRisk($items[0]['reasons']));
        $this->assertTrue(QuarantineDigestService::isHighRisk($items[1]['reasons']), 'unmatched item fails closed');
    }

    /** Long non-ASCII subjects used to never match (byte clip vs. character clip). */
    public function testLongNonAsciiSubjectMatches()
    {
        $subject = str_repeat('Zażółć gęślą jaźń ', 40); // 720 chars, > 500 bytes and > 500 chars
        $this->log('jan@firma.pl', 'x@evil.pl', $subject, [['rule' => 'attachment_office_macro', 'score' => 6]]);

        $items = $this->service()->attachImapScores([self::item('x@evil.pl', $subject)], 'jan@firma.pl');

        $this->assertSame('attachment_office_macro', $items[0]['reasons'][0]['rule']);
        $this->assertTrue(QuarantineDigestService::isHighRisk($items[0]['reasons']));
    }

    public function testSubjectMatchVariants()
    {
        $subject = str_repeat('ąb', 300); // 900 bytes, 600 chars
        $this->assertTrue(QuarantineService::subjectMatches(mb_substr($subject, 0, 500, 'UTF-8'), $subject));
        $this->assertTrue(QuarantineService::subjectMatches(substr($subject, 0, 500), $subject));
        // Legacy byte clip with the split character dropped by MySQL.
        $this->assertTrue(QuarantineService::subjectMatches(substr($subject, 0, 499), $subject));
        $this->assertTrue(QuarantineService::subjectMatches('Krótki', 'Krótki'));
        $this->assertFalse(QuarantineService::subjectMatches('Krótki', 'Krótki temat'));
        $this->assertFalse(QuarantineService::subjectMatches('', 'Temat'));
    }

    public function testEmptyLogReasonsFailClosed()
    {
        $this->log('jan@firma.pl', 'x@evil.pl', 'Faktura', []);
        $items = $this->service()->attachImapScores([self::item('x@evil.pl', 'Faktura')], 'jan@firma.pl');
        $this->assertTrue(QuarantineDigestService::isHighRisk($items[0]['reasons']));
    }

    private function legacyImapFolder(int $uidValidity): MailboxInterface
    {
        $this->config->set('imap', 'imap.firma.pl');
        $this->config->set('login', 'jan');
        $this->config->set('email', 'jan@firma.pl');

        $folder = $this->createMock(MailboxInterface::class);
        $folder->method('getStatus')->willReturn((object)['uidvalidity' => $uidValidity]);
        $conn = $this->createMock(ConnectionInterface::class);
        $conn->method('getMailbox')->willReturn($folder);
        $this->connection->method('getConnection')->willReturn($conn);
        return $folder;
    }

    public function testDigestActionRefusedAfterUidValidityChange()
    {
        $folder = $this->legacyImapFolder(222);
        $folder->expects($this->never())->method('getMessage');

        $service = $this->service();
        $this->assertFalse($service->release('imap', '42', true, 111)['success']);
        $this->assertSame(QuarantineService::NOT_FOUND, $service->delete('imap', '42', 111)['message']);
    }

    public function testDigestActionProceedsWhenUidValidityMatches()
    {
        $folder = $this->legacyImapFolder(222);
        // Reaching getMessage() means the check passed (the mock message is then not found).
        $folder->expects($this->once())->method('getMessage')->with(42)->willThrowException(new \RuntimeException('gone'));

        $this->service()->delete('imap', '42', 222);
    }
}
