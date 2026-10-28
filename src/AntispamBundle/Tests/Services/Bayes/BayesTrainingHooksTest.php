<?php

namespace AntispamBundle\Tests\Services\Bayes;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\EventListener\Message\CheckBayes;
use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use AntispamBundle\Services\Bayes\BayesService;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\DnsblService;
use AntispamBundle\Services\HeaderAnalyzer;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\ImpersonationAnalyzer;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\RawMessageScanner;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SpamFolderService;
use AntispamBundle\Services\SpamSignalService;
use AntispamBundle\Services\SshService;
use AntispamBundle\Services\UrlAnalyzer;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\Message\EmailAddress;
use Ddeboer\Imap\MessageInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Every user verdict that reaches the panel trains the classifier; the
 * pipeline listener and the plugin scanner score with it.
 */
class BayesTrainingHooksTest extends BayesTestCase
{
    private function plugin(BayesService $bayes): PluginService
    {
        return new PluginService($this->em, $this->createMock(CacheItemPoolInterface::class), $this->createMock(SpamSignalService::class), 'secret', $this->config, null, $bayes);
    }

    public function testPluginReportsTrainOnlyForLoggedInMailboxes()
    {
        $bayes = $this->bayes();
        $account = $this->account('jan@firma.pl');
        [$spam, $ham] = [self::spamCorpus(1)[0], self::hamCorpus(1)[0]];

        $this->assertArrayNotHasKey('bayes', $this->plugin($bayes)->learn($spam, PluginService::VERDICT_SPAM, null, '1.2.3.4'), 'anonymous report');
        $this->assertSame(0, $bayes->stats()['spam']);

        $this->assertTrue($this->plugin($bayes)->learn($spam, PluginService::VERDICT_SPAM, $account)['bayes']);
        $this->assertTrue($this->plugin($bayes)->learn($ham, PluginService::VERDICT_HAM, $account, null, 'phishing')['bayes']);
        $this->assertSame([1, 1], [$bayes->stats()['spam'], $bayes->stats()['ham']]);
        $this->assertSame(['phishing', 'plugin'], $this->em->getConnection()->fetchFirstColumn('SELECT source FROM antispam_bayes_message ORDER BY source'));
    }

    /** IMAP message mock built from a raw source. */
    private function imapMessage(string $raw)
    {
        $f = \AntispamBundle\Services\Bayes\BayesTokenizer::fieldsFromRaw($raw);
        [$box, $host] = explode('@', $f['from']);
        $msg = $this->createMock(MessageInterface::class);
        $msg->method('getFrom')->willReturn(new EmailAddress($box, $host));
        $msg->method('getSubject')->willReturn($f['subject']);
        $msg->method('getId')->willReturn($f['message_id']);
        $msg->method('getRawHeaders')->willReturn(explode("\r\n\r\n", $raw, 2)[0]);
        $msg->method('getBodyText')->willReturn($f['text']);
        $msg->method('getSize')->willReturn(strlen($raw));
        return $msg;
    }

    private function legacyConnection(MessageInterface $msg): ConnectionService
    {
        $this->config->set('imap', 'imap.firma.pl');
        $this->config->set('login', 'jan');
        $this->config->set('email', 'jan@firma.pl');
        $folder = $this->createMock(MailboxInterface::class);
        $folder->method('getMessage')->willReturn($msg);
        $conn = $this->createMock(ConnectionInterface::class);
        $conn->method('getMailbox')->willReturn($folder);
        $conn->method('hasMailbox')->willReturn(true);
        $service = $this->createMock(ConnectionService::class);
        $service->method('getConnection')->willReturn($conn);
        return $service;
    }

    private function quarantine(ConnectionService $connection, BayesService $bayes): QuarantineService
    {
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getQuarantineFolderName')->willReturn('QUARANTINE');
        $inbox->method('getSpamFolderName')->willReturn('SPAM');
        return new QuarantineService($this->em, $this->config, $this->createMock(SshService::class), $connection, $inbox,
            $this->createMock(MessageService::class), $this->createMock(ImapScanService::class), null, $bayes);
    }

    public function testQuarantineReleaseTrainsHamBeforeTheMove()
    {
        $bayes = $this->bayes();
        $msg = $this->imapMessage(self::hamCorpus(1)[0]);
        $msg->expects($this->once())->method('move');
        $this->assertTrue($this->quarantine($this->legacyConnection($msg), $bayes)->release('imap', '7')['success']);
        $this->assertSame([0, 1], [$bayes->stats()['spam'], $bayes->stats()['ham']]);
    }

    public function testSpamReleaseTrainsHam()
    {
        $bayes = $this->bayes();
        $msg = $this->imapMessage(self::hamCorpus(1)[0]);
        $connection = $this->legacyConnection($msg);
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getSpamFolderName')->willReturn('SPAM');
        $service = new SpamFolderService($this->em, $this->quarantine($connection, $bayes), $this->createMock(SshService::class),
            $this->createMock(ImapScanService::class), $connection, $inbox, $this->createMock(MessageService::class), $bayes);
        $this->assertTrue($service->release('imap', '7')['success']);
        $this->assertSame(1, $bayes->stats()['ham']);
    }

    public function testPipelineListenerScores()
    {
        $bayes = $this->bayes();
        $this->train($bayes);
        $scoring = new ScoringService($this->em, $this->config);
        $listener = new CheckBayes($bayes, $scoring);

        $event = new MessageEvent($this->imapMessage(self::raw('Wygrana nagroda dla Ciebie', 'Odbierz darmową nagrodę, tani kredyt bez BIK https://promo.casino-win.ru/x viagra promocja', 'x@casino-win.ru')), 'jan@firma.pl');
        $listener->check($event);
        $this->assertSame(5, $event->getSpamscore());
        $this->assertStringStartsWith('bayes:0.9', $event->getReasons()[0]['rule']);

        $white = new MessageEvent($this->imapMessage(self::spamCorpus(1)[0]), 'jan@firma.pl');
        $white->setWhitelist(true);
        $listener->check($white);
        $this->assertSame(0, $white->getSpamscore());

        $this->config->set('scoring.enabled', false);
        $off = new MessageEvent($this->imapMessage(self::spamCorpus(1)[0]), 'jan@firma.pl');
        (new CheckBayes($bayes, new ScoringService($this->em, $this->config)))->check($off);
        $this->assertSame(0, $off->getSpamscore());
    }

    public function testPluginScannerScores()
    {
        $bayes = $this->bayes();
        $this->train($bayes);
        foreach (['scoring.header_check_enabled', 'scoring.dnsbl_enabled', 'impersonation.enabled', 'url.enabled', 'attachment.policy_enabled'] as $k) {
            $this->config->set($k, false);
        }
        $scoring = new ScoringService($this->em, $this->config);
        $scanner = new RawMessageScanner($this->em, new HeaderAnalyzer($scoring), new DnsblService($this->em), $scoring, $this->createMock(SpamSignalService::class),
            new ImpersonationAnalyzer(), new UrlAnalyzer(), new AttachmentPolicyAnalyzer(), $this->createMock(CertHoleService::class), null, $bayes);

        $result = $scanner->scan(self::raw('Wygrana nagroda', 'Odbierz darmową nagrodę, tani kredyt bez BIK viagra promocja', 'x@casino-win.ru'), 'jan@firma.pl');
        $this->assertSame(5, $result['score']);
        $this->assertSame('quarantine', $result['decision']);
        $this->assertContains('bayes:0.99', array_column($result['reasons'], 'rule'));
    }
}
