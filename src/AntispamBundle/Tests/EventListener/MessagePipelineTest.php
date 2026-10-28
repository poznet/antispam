<?php

namespace AntispamBundle\Tests\EventListener;

use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\EventListener\Message\ApplyScoreDecision;
use AntispamBundle\EventListener\Message\CheckAttachmentsVirusTotal;
use AntispamBundle\EventListener\Message\CheckDnsbl;
use AntispamBundle\EventListener\Message\CheckEmailBlacklist;
use AntispamBundle\EventListener\Message\CheckWhitelist;
use AntispamBundle\Services\DnsblService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\RawMessageParser;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\VirusTotalService;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\Message\EmailAddress;
use Ddeboer\Imap\MessageInterface;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class MessagePipelineTest extends KernelTestCase
{
    private function message($fromMailbox, $fromHost, $raw = '')
    {
        $msg = $this->createMock(MessageInterface::class);
        $msg->method('getFrom')->willReturn(new EmailAddress($fromMailbox, $fromHost));
        $msg->method('getId')->willReturn('<1@' . $fromHost . '>');
        $msg->method('getRawHeaders')->willReturn($raw);
        return $msg;
    }

    private function em(array $rules)
    {
        $repo = $this->createMock(EntityRepository::class);
        $repo->method('findBy')->willReturn($rules);
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn($repo);
        return $em;
    }

    public function testWhitelistMatchesFromNotSender()
    {
        $rule = (new Whitelist())->setHost('zaufany.pl');
        $listener = new CheckWhitelist($this->em([$rule]), $this->createMock(MessageService::class));

        // "Sender: x@zaufany.pl" is not read at all - only From counts.
        $event = new MessageEvent($this->message('x', 'evil.example'), 'box@firma.pl');
        $listener->check($event);
        $this->assertFalse($event->isWhitelist());

        $event = new MessageEvent($this->message('Biuro', 'Zaufany.PL'), 'box@firma.pl');
        $event->setInitialScan(true); // no counter update (needs a real EntityManager)
        $listener->check($event);
        $this->assertTrue($event->isWhitelist());
        $this->assertTrue($event->isPropagationStopped());
    }

    public function testEmailBlacklistMatchesFromAddress()
    {
        $rule = (new EmailBlacklist())->setBlacklistemail('spam@evil.example')->setScore(10);
        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('isScoringEnabled')->willReturn(true);
        $listener = new CheckEmailBlacklist($this->em([$rule]), $this->createMock(MessageService::class), $scoring);

        $event = new MessageEvent($this->message('SPAM', 'evil.example'), 'box@firma.pl');
        $event->setInitialScan(true);
        $listener->check($event);
        $this->assertTrue($event->isBlacklist());
        $this->assertSame(10, $event->getSpamscore());
    }

    public function testFailedQuarantineMoveIsRethrownSoTheMessageIsRetried()
    {
        $log = new SpamScoreLog();
        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('decide')->willReturnCallback(function (MessageEvent $e) use ($log) {
            $e->setScoreLog($log);
            return SpamScoreLog::DECISION_QUARANTINE;
        });
        $scoring->expects($this->once())->method('recordOutcome')->with($log, SpamScoreLog::OUTCOME_MOVE_FAILED);
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getQuarantineFolder')->willReturn($this->createMock(MailboxInterface::class));

        $msg = $this->message('a', 'b.pl');
        $msg->method('move')->willThrowException(new \RuntimeException('NO [OVERQUOTA]'));
        $event = new MessageEvent($msg, 'box@firma.pl');

        $this->expectExceptionMessage('OVERQUOTA');
        (new ApplyScoreDecision($scoring, $inbox))->decide($event);
    }

    public function testDnsblUsesRawReceivedHeaders()
    {
        $raw = "Received: from localhost (localhost [127.0.0.1]) by mx.firma.pl (amavis)\r\n"
            . "Received: from mail.evil.example (mail.evil.example [198.51.100.9])\r\n"
            . "\tby mx.firma.pl ([203.0.113.1]) with ESMTPS id 123\r\n"
            . "From: <a@evil.example>\r\n";
        $dnsbl = $this->createMock(DnsblService::class);
        $dnsbl->expects($this->once())->method('scoreForIp')->with('198.51.100.9')->willReturn(0);
        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('isScoringEnabled')->willReturn(true);
        $scoring->method('isDnsblEnabled')->willReturn(true);

        (new CheckDnsbl($dnsbl, $scoring))->check(new MessageEvent($this->message('a', 'evil.example', $raw), 'box@firma.pl'));
    }

    public function testConnectingIpExtractor()
    {
        $this->assertSame('198.51.100.9', RawMessageParser::connectingIpFromReceived([
            'from [10.1.2.3] by relay.firma.pl',
            'from mail.evil.example (HELO 192.0.2.300) (mail.evil.example [198.51.100.9]) by relay',
        ]));
        // The "by" part is the receiving server, never the sender.
        $this->assertNull(RawMessageParser::connectingIpFromReceived(['by mx.firma.pl (203.0.113.1) with LMTP']));
        $this->assertSame('198.51.100.20', RawMessageParser::connectingIpFromReceived(['from x (198.51.100.20) by mx']));
        $this->assertNull(RawMessageParser::connectingIpFromReceived([]));
        // Plugin path uses the very same extractor.
        $p = new RawMessageParser("Received: from a ([192.168.1.5]) by b\r\nReceived: from c\r\n (c [198.51.100.30]) by d\r\n\r\nbody");
        $this->assertSame('198.51.100.30', $p->getConnectingIp());
    }

    public function testVirusTotalVerdictIsLookedUpOncePerHash()
    {
        $vt = $this->createMock(VirusTotalService::class);
        $vt->expects($this->once())->method('lookupHash')
            ->willReturn(['found' => true, 'malicious' => 0, 'suspicious' => 0, 'total' => 70, 'error' => null]);
        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('isScoringEnabled')->willReturn(true);
        $scoring->method('isVirusTotalEnabled')->willReturn(true);
        $scoring->method('getVirusTotalApiKey')->willReturn('key');
        $scoring->method('getVirusTotalThreshold')->willReturn(3);

        $listener = $this->getMockBuilder(CheckAttachmentsVirusTotal::class)
            ->setConstructorArgs([$vt, $scoring])
            ->onlyMethods(['extractAttachments', 'decodeAttachment'])
            ->getMock();
        $listener->method('extractAttachments')->willReturn([new \stdClass()]);
        $listener->method('decodeAttachment')->willReturn('same bytes');

        $listener->check(new MessageEvent($this->message('a', 'b.pl'), 'box@firma.pl'));
        $listener->check(new MessageEvent($this->message('c', 'd.pl'), 'box@firma.pl'));
    }

    public function testScoreLogClipsToColumnSizesOnCharacterBoundaries()
    {
        $log = (new SpamScoreLog())
            ->setSender(str_repeat('ż', 300) . '@x.pl')
            ->setSubject(str_repeat('ą', 600))
            ->setAccountEmail("bad\xC3");

        $this->assertSame(255, mb_strlen($log->getSender(), 'UTF-8'));
        $this->assertSame(500, mb_strlen($log->getSubject(), 'UTF-8'));
        $this->assertTrue(mb_check_encoding($log->getSubject(), 'UTF-8'));
        $this->assertTrue(mb_check_encoding($log->getAccountEmail(), 'UTF-8'));
        $this->assertNull((new SpamScoreLog())->setSubject(null)->getSubject());
    }

    /** The order the pipeline relies on (services.yaml priorities). */
    public function testListenerOrder()
    {
        self::bootKernel();
        $names = [];
        foreach (self::getContainer()->get('event_dispatcher')->getListeners('antispam.check.message') as $listener) {
            $names[] = is_array($listener) ? (new \ReflectionClass($listener[0]))->getShortName() : 'closure';
        }
        $this->assertSame([
            'CheckIfIsAlreadyChecked', 'CheckWhitelist', 'CheckEmailWhitelist', 'CheckBlacklist', 'CheckEmailBlacklist',
            'CheckHeaders', 'CheckImpersonation', 'CheckDnsbl', 'CheckUrls', 'CheckSharedFeed', 'CheckCertHole',
            'CheckAttachmentPolicy', 'CheckAttachments', 'CheckAttachmentsVirusTotal', 'ApplyScoreDecision',
            'RecordSpamSignals', 'MoveToSpam', 'SetAsChecked',
        ], $names);
    }
}
