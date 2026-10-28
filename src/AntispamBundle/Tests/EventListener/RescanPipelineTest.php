<?php

namespace AntispamBundle\Tests\EventListener;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\EventListener\Message\CheckIfIsAlreadyChecked;
use AntispamBundle\EventListener\Message\MoveToSpam;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\ScoringService;
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
}
