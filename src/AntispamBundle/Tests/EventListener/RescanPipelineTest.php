<?php

namespace AntispamBundle\Tests\EventListener;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\EventListener\Message\CheckDnsbl;
use AntispamBundle\EventListener\Message\CheckHeaders;
use AntispamBundle\EventListener\Message\CheckIfIsAlreadyChecked;
use AntispamBundle\EventListener\Message\CheckUrls;
use AntispamBundle\EventListener\Message\MoveToSpam;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\DnsblService;
use AntispamBundle\Services\HeaderAnalyzer;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\UrlAnalyzer;
use AntispamBundle\Tests\Support\JobsDatabase;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\MessageInterface;
use PHPUnit\Framework\TestCase;

/**
 * The pipeline during a full rescan: markers ignored, spam moved even with
 * "delete spam" on, decisions logged as `rescan` and kept out of the stats.
 */
class RescanPipelineTest extends TestCase
{
    private function rescanEvent(MessageInterface $msg, ?bool $deleteSpam = false): MessageEvent
    {
        $event = new MessageEvent($msg, 'box@firma.pl', null, $deleteSpam);
        $event->setRescan(true);
        return $event;
    }

    public function testRescanImpliesInitialScan()
    {
        $event = $this->rescanEvent($this->createMock(MessageInterface::class));
        $this->assertTrue($event->isRescan());
        $this->assertTrue($event->isInitialScan());
        $plain = new MessageEvent($this->createMock(MessageInterface::class));
        $this->assertFalse($plain->isRescan());
        $this->assertFalse($plain->isInitialScan());
    }

    public function testMarkersAreIgnored()
    {
        $ms = $this->createMock(MessageService::class);
        $ms->method('isChecked')->willReturn(true);
        $listener = new CheckIfIsAlreadyChecked($ms);

        $event = $this->rescanEvent($this->createMock(MessageInterface::class));
        $listener->check($event);
        $this->assertFalse($event->isCheckedbefore());
        $this->assertFalse($event->isPropagationStopped());

        $normal = new MessageEvent($this->createMock(MessageInterface::class), 'box@firma.pl');
        $listener->check($normal);
        $this->assertTrue($normal->isCheckedbefore());
    }

    public function testSpamIsMovedEvenWhenTheGlobalDeleteSettingIsOn()
    {
        $config = $this->createMock(ConfigService::class);
        $config->method('get')->willReturn(true); // `delete` = on
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getSpamFolder')->willReturn($this->createMock(MailboxInterface::class));
        $msg = $this->createMock(MessageInterface::class);
        $msg->expects($this->never())->method('delete');
        $msg->expects($this->once())->method('move');

        $event = $this->rescanEvent($msg); // ImapScanService::rescan passes deleteSpam = false
        $event->setSpam(true);
        (new MoveToSpam($config, $inbox, $this->createMock(ScoringService::class)))->move($event);
        $this->assertTrue($event->isDelete(), 'left INBOX');
    }

    public function testDecisionsAreLoggedAsRescanAndKeptOutOfTheStats()
    {
        $db = new JobsDatabase();
        $scoring = new ScoringService($db->em);
        $event = $this->rescanEvent($this->createMock(MessageInterface::class));
        $event->setSpamscore(50);
        $this->assertSame(SpamScoreLog::DECISION_SPAM, $scoring->decide($event, [], 'a@spam.pl', 'x'));
        $log = $event->getScoreLog();
        $this->assertSame([SpamScoreLog::SOURCE_RESCAN, true], [$log->getSource(), $log->isInitialScan()]);

        $normal = new MessageEvent($this->createMock(MessageInterface::class), 'box@firma.pl');
        $normal->setSpamscore(50);
        $scoring->decide($normal, [], 'a@spam.pl', 'x');
        $this->assertSame(SpamScoreLog::SOURCE_SCAN, $normal->getScoreLog()->getSource());

        $repo = $db->em->getRepository(SpamScoreLog::class);
        $this->assertSame(1, $repo->statsByDecision(new \DateTime('-1 day'))['spam'], 'only the regular scan counts');
        $this->assertSame(1, array_sum(array_column($repo->dailyCounts(1), 'cnt')));
    }

    private function scoring(bool $skipUrlLookups = true): ScoringService
    {
        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('isScoringEnabled')->willReturn(true);
        $scoring->method('isDnsblEnabled')->willReturn(true);
        $scoring->method('isUrlCheckEnabled')->willReturn(true);
        $scoring->method('isRescanUrlLookupSkipped')->willReturn($skipUrlLookups);
        $scoring->method('getUrlConfig')->willReturn(['dbl_enabled' => true, 'gsb_enabled' => true]);
        return $scoring;
    }

    public function testRescanSkipsTheDnsblLookup()
    {
        // Today's reputation of the IP that delivered old mail means nothing - and cost DNS per message.
        $dnsbl = $this->createMock(DnsblService::class);
        $dnsbl->expects($this->never())->method('scoreForIp');
        $msg = $this->createMock(MessageInterface::class);
        $msg->expects($this->never())->method('getRawHeaders');
        (new CheckDnsbl($dnsbl, $this->scoring()))->check($this->rescanEvent($msg));
    }

    public function testRescanTurnsOffLinkDomainLookupsBySetting()
    {
        $msg = $this->createMock(MessageInterface::class);
        $msg->method('getBodyText')->willReturn('http://example.com/x');
        foreach ([true => [false, false], false => [true, true]] as $skip => $expected) {
            $seen = null;
            $analyzer = $this->createMock(UrlAnalyzer::class);
            $analyzer->method('analyze')->willReturnCallback(function ($html, $text, $config) use (&$seen) {
                $seen = [$config['dbl_enabled'], $config['gsb_enabled']];
                return ['score' => 0, 'reasons' => []];
            });
            (new CheckUrls($analyzer, $this->scoring((bool)$skip)))->check($this->rescanEvent($msg));
            $this->assertSame($expected, $seen, $skip ? 'setting on' : 'setting off');
        }
    }

    public function testBlacklistedMessageInARescanSkipsTheContentChecks()
    {
        // The verdict is final: no body / headers are fetched from IMAP.
        $msg = $this->createMock(MessageInterface::class);
        $msg->expects($this->never())->method('getBodyText');
        $msg->expects($this->never())->method('getBodyHtml');
        $msg->expects($this->never())->method('getRawHeaders');
        $event = $this->rescanEvent($msg);
        $event->setBlacklist(true);
        $event->setSpam(true);
        $this->assertTrue($event->isDecidedInRescan());
        (new CheckUrls($this->createMock(UrlAnalyzer::class), $this->scoring()))->check($event);
        (new CheckHeaders($this->createMock(HeaderAnalyzer::class), $this->scoring()))->check($event);

        $normal = new MessageEvent($msg, 'box@firma.pl');
        $normal->setBlacklist(true);
        $this->assertFalse($normal->isDecidedInRescan(), 'regular scans keep every reason');
    }
}
