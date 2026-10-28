<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\DigestTokenService;
use AntispamBundle\Services\DnsblService;
use AntispamBundle\Services\HeaderAnalyzer;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\ImpersonationAnalyzer;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MailboxSettings;
use AntispamBundle\Services\MailboxSettingsResolver;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\QuarantineDigestService;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\RawMessageScanner;
use AntispamBundle\Services\RetroactiveSpamService;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SpamSignalService;
use AntispamBundle\Services\SshService;
use AntispamBundle\Services\UrlAnalyzer;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\ImapResourceInterface;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\MessageInterface;
use Ddeboer\Imap\MessageIterator;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Twig\Environment;

/**
 * Per-mailbox settings (Konta → Ustawienia skrzynki): resolver precedence
 * and every consumer using the account's effective values.
 */
class MailboxSettingsTest extends TestCase
{
    private EntityManager $em;
    private ConfigService $config;
    private ScoringService $scoring;
    private MailboxSettingsResolver $resolver;

    protected function setUp(): void
    {
        $setup = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $setup);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->config = new ConfigService($this->em);
        $this->scoring = new ScoringService($this->em, $this->config);
        $this->resolver = new MailboxSettingsResolver($this->scoring, $this->config, $this->em);
    }

    private function account(string $email, string $type = Account::CONNECTION_IMAP): Account
    {
        $a = (new Account())->setName($email)->setEmail($email)->setConnectionType($type);
        $this->em->persist($a);
        $this->em->flush();
        return $a;
    }

    // --- resolver ----------------------------------------------------------

    public function testAccountWithoutOverridesInheritsTheGlobalSettings()
    {
        $this->config->set('scoring.spam_threshold', 12);
        $this->config->set('scoring.quarantine_threshold', 4);
        $this->config->set('digest.enabled', true);
        $s = $this->resolver->forAccount($this->account('jan@firma.pl'));

        $this->assertSame([12, 4, true, false, true, 'jan@firma.pl', null], [$s->spamThreshold, $s->quarantineThreshold, $s->scoringEnabled, $s->deleteSpam, $s->digestEnabled, $s->digestRecipient, $s->digestHour]);
        $this->assertFalse($s->hasOverrides());
    }

    public function testAccountOverridesWinOverGlobalSettings()
    {
        $this->config->set('digest.enabled', true);
        $a = $this->account('jan@firma.pl')->setSpamThreshold(6)->setQuarantineThreshold(2)->setScoringEnabled(false)
            ->setDigestEnabled(false)->setDigestRecipient('szef@firma.pl')->setDigestHour(14)->setDeleteSpam(true);
        $s = $this->resolver->forAccount($a);

        $this->assertSame([6, 2, false, true, false, 'szef@firma.pl', 14], [$s->spamThreshold, $s->quarantineThreshold, $s->scoringEnabled, $s->deleteSpam, $s->digestEnabled, $s->digestRecipient, $s->digestHour]);
        $this->assertTrue($s->isOverridden('digest_recipient'));
        $this->assertSame(MailboxSettingsResolver::FIELDS, array_keys($s->overrides));
    }

    public function testOnlyOneThresholdOverriddenKeepsTheOtherGlobal()
    {
        $s = $this->resolver->forAccount($this->account('jan@firma.pl')->setSpamThreshold(20));
        $this->assertSame([20, ScoringService::DEFAULT_QUARANTINE_THRESHOLD], [$s->spamThreshold, $s->quarantineThreshold]);
        $this->assertSame(['spam_threshold' => 20], $s->overrides);
    }

    public function testSshAccountNeverDeletesSpamAndLegacyMailboxIsGlobal()
    {
        $this->config->set('delete', true);
        $this->config->set('email', 'biuro@firma.pl');
        $this->config->set('digest.imap_recipient', 'it@firma.pl');

        $ssh = $this->account('ssh@firma.pl', Account::CONNECTION_SSH)->setDeleteSpam(true);
        $this->assertFalse($this->resolver->forAccount($ssh)->deleteSpam);

        $legacy = $this->resolver->forAccount(null);
        $this->assertTrue($legacy->deleteSpam);
        $this->assertSame('it@firma.pl', $legacy->digestRecipient);
        $this->assertSame([], $legacy->overrides);
        $this->assertSame(ScoringService::DEFAULT_SPAM_THRESHOLD, $this->resolver->forEmail('nobody@firma.pl')->spamThreshold);
        $ssh->setSpamThreshold(7);
        $this->em->flush();
        $this->assertSame(7, $this->resolver->forEmail('ssh@firma.pl')->spamThreshold);
    }

    public function testScopeIsRestoredAfterTheRunAlsoOnException()
    {
        $a = $this->account('jan@firma.pl')->setSpamThreshold(6)->setScoringEnabled(false);
        $seen = $this->resolver->within($a, fn () => [$this->scoring->getSpamThreshold(), $this->scoring->isScoringEnabled(), $this->scoring->classify(6)]);
        $this->assertSame([6, false, SpamScoreLog::DECISION_SPAM], $seen);
        $this->assertSame(10, $this->scoring->getSpamThreshold());
        $this->assertSame(SpamScoreLog::DECISION_QUARANTINE, $this->scoring->classify(6));

        try {
            $this->resolver->within($a, function () { throw new \RuntimeException('boom'); });
            $this->fail('expected the exception');
        } catch (\RuntimeException $e) {
            $this->assertNull($this->scoring->getMailboxSettings());
        }
    }

    // --- validation --------------------------------------------------------

    public function testEmptyFieldsMeanInherit()
    {
        [$values, $errors] = $this->resolver->parseOverrides(['spam_threshold' => '', 'scoring_enabled' => '', 'digest_recipient' => '  ']);
        $this->assertSame([], $errors);
        $this->assertSame(array_fill_keys(MailboxSettingsResolver::FIELDS, null), $values);
    }

    public function testValidOverridesAreParsed()
    {
        [$values, $errors] = $this->resolver->parseOverrides(['spam_threshold' => '8', 'quarantine_threshold' => '0', 'scoring_enabled' => '0', 'digest_enabled' => '1', 'digest_recipient' => 'szef@firma.pl', 'digest_hour' => '0']);
        $this->assertSame([], $errors);
        $this->assertSame(['spam_threshold' => 8, 'quarantine_threshold' => 0, 'scoring_enabled' => false, 'digest_enabled' => true, 'digest_recipient' => 'szef@firma.pl', 'digest_hour' => 0], $values);
    }

    public function testQuarantineMustStayBelowSpamCountingTheInheritedValue()
    {
        $this->config->set('scoring.spam_threshold', 10);
        $this->config->set('scoring.quarantine_threshold', 5);

        [, $errors] = $this->resolver->parseOverrides(['spam_threshold' => '5']);           // q 5 (global) >= s 5
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('niższy niż próg spamu (5)', $errors[0]);
        [, $errors] = $this->resolver->parseOverrides(['quarantine_threshold' => '10']);    // q 10 >= s 10 (global)
        $this->assertCount(1, $errors);
        [, $errors] = $this->resolver->parseOverrides(['spam_threshold' => '4', 'quarantine_threshold' => '3']);
        $this->assertSame([], $errors);
    }

    public function testInvalidValuesAreRejected()
    {
        [$values, $errors] = $this->resolver->parseOverrides(['spam_threshold' => '0', 'quarantine_threshold' => '-1', 'scoring_enabled' => 'yes', 'digest_enabled' => '2', 'digest_recipient' => 'nie-adres', 'digest_hour' => '24']);
        $this->assertCount(6, $errors);
        $this->assertSame(array_fill_keys(MailboxSettingsResolver::FIELDS, null), $values);
        [, $errors] = $this->resolver->parseOverrides(['spam_threshold' => '1001']);
        $this->assertCount(1, $errors);
    }

    // --- consumers ---------------------------------------------------------

    public function testHeaderCapUsesTheMailboxThresholds()
    {
        $analyzer = new HeaderAnalyzer($this->scoring);
        $raw = "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\r\nFrom: <x@bank.pl>\r\nMessage-ID: <6@bank.pl>\r\n";

        $this->assertSame(9, $analyzer->analyzeRaw($raw)['score']);
        $a = $this->account('jan@firma.pl')->setSpamThreshold(7)->setQuarantineThreshold(3);
        $this->assertSame(6, $this->resolver->within($a, fn () => $analyzer->analyzeRaw($raw))['score']);
    }

    public function testImapScanDecidesWithTheAccountThresholds()
    {
        $account = $this->account('jan@firma.pl')->setSpamThreshold(6)->setDeleteSpam(true);
        $connection = $this->createMock(ConnectionInterface::class);
        $seen = [];

        $scan = $this->getMockBuilder(ImapScanService::class)
            ->setConstructorArgs([new EventDispatcher(), $this->createMock(ConnectionService::class), $this->config,
                $this->createMock(CryptoService::class), $this->createMock(MessageService::class), null,
                sys_get_temp_dir() . '/antispam-locks-' . bin2hex(random_bytes(4)), $this->resolver])
            ->onlyMethods(['connect', 'scan'])
            ->getMock();
        $scan->method('connect')->willReturn($connection);
        $scan->method('scan')->willReturnCallback(function ($conn, $email, $deleteSpam) use (&$seen) {
            // What ApplyScoreDecision does for a message scoring 7.
            $event = new MessageEvent($this->createMock(MessageInterface::class), $email, $conn, $deleteSpam);
            $event->setSpamscore(7);
            $seen = [$deleteSpam, $this->scoring->decide($event, [['rule' => 'x', 'score' => 7]], 'a@b.pl', 's'), $event->isSpam()];
            return ['total' => 0, 'checked' => 0, 'skipped' => 0, 'errors' => []];
        });

        $scan->scanAccount($account);

        $this->assertSame([true, SpamScoreLog::DECISION_SPAM, true], $seen);
        $this->assertNull($this->scoring->getMailboxSettings(), 'scope must not leak past the scan');
        // Global threshold (10): the same score only quarantines.
        $event = new MessageEvent($this->createMock(MessageInterface::class), 'biuro@firma.pl');
        $event->setSpamscore(7);
        $this->assertSame(SpamScoreLog::DECISION_QUARANTINE, $this->scoring->decide($event, [], 'a@b.pl', 's'));
    }

    private function rawScanner(): RawMessageScanner
    {
        // Only the blacklist counts in these tests.
        foreach (['scoring.header_check_enabled', 'impersonation.enabled', 'scoring.dnsbl_enabled', 'url.enabled', 'attachment.policy_enabled'] as $key) {
            $this->config->set($key, '0');
        }
        return new RawMessageScanner(
            $this->em, new HeaderAnalyzer($this->scoring), $this->createMock(DnsblService::class), $this->scoring,
            new SpamSignalService($this->em, $this->config), $this->createMock(ImpersonationAnalyzer::class),
            $this->createMock(UrlAnalyzer::class), $this->createMock(AttachmentPolicyAnalyzer::class),
            new CertHoleService($this->em, $this->config), $this->resolver
        );
    }

    public function testPluginCheckUsesTheLoggedInAccountSettings()
    {
        $this->em->persist((new Blacklist())->setEmail('*')->setHost('evil.example')->setScore(6));
        $this->em->flush();
        $raw = "From: Spammer <x@evil.example>\r\nSubject: hi\r\nMessage-ID: <1@evil.example>\r\n\r\nbody\r\n";
        $scanner = $this->rawScanner();

        $inherit = $this->account('ola@firma.pl');
        $res = $scanner->scan($raw, 'ola@firma.pl', $inherit);
        $this->assertSame(['quarantine', 10], [$res['decision'], $res['spam_threshold']]);

        $strict = $this->account('jan@firma.pl')->setSpamThreshold(6);
        $res = $scanner->scan($raw, 'jan@firma.pl', $strict);
        $this->assertSame(['spam', 6], [$res['decision'], $res['spam_threshold']]);

        // Scoring off for the mailbox: a blacklist hit is spam outright.
        $off = $this->account('off@firma.pl')->setScoringEnabled(false)->setSpamThreshold(50);
        $this->em->flush();
        $res = $scanner->scan($raw, 'off@firma.pl'); // looked up by e-mail
        $this->assertSame('spam', $res['decision']);
        $this->assertNull($this->scoring->getMailboxSettings());
    }

    public function testAgentSettingsExportIsPerAccount()
    {
        $this->config->set('scoring.spam_threshold', 10);
        $exporter = new AgentRulesExporter($this->em, $this->scoring, $this->resolver);
        $ssh = $this->account('ssh@firma.pl', Account::CONNECTION_SSH)->setSpamThreshold(8)->setQuarantineThreshold(4)->setScoringEnabled(false);
        $this->em->flush();

        $settings = $exporter->export('ssh@firma.pl', $ssh)['settings'];
        $this->assertSame([8, 4, false], [$settings['spam_threshold'], $settings['quarantine_threshold'], $settings['scoring_enabled']]);
        // CERT score defaults to the mailbox spam threshold.
        $this->assertSame(8, $settings['cert_score']);
        $this->assertSame(8, $exporter->export('ssh@firma.pl')['settings']['spam_threshold']);

        $other = $this->account('inny@firma.pl', Account::CONNECTION_SSH);
        $this->assertSame([10, true], [$exporter->export('inny@firma.pl', $other)['settings']['spam_threshold'], $exporter->export('inny@firma.pl', $other)['settings']['scoring_enabled']]);
    }

    public function testRetroactivePassUsesEachMailboxThreshold()
    {
        $this->config->set('scoring.spam_threshold', 10);
        $strict = $this->account('jan@firma.pl')->setSpamThreshold(6);
        $this->account('ola@firma.pl');
        $this->em->flush();
        $rule = (new EmailBlacklist())->setEmail('*')->setBlacklistemail('x@evil.example')->setScore(6);
        $this->em->persist($rule);
        $this->em->flush();

        $connected = [];
        $mailbox = $this->createMock(MailboxInterface::class);
        $mailbox->method('getMessages')->willReturn(new MessageIterator($this->createMock(ImapResourceInterface::class), []));
        $connection = $this->createMock(ConnectionInterface::class);
        $connection->method('getMailbox')->willReturn($mailbox);
        $imap = $this->createMock(ImapScanService::class);
        $imap->method('connect')->willReturnCallback(function (Account $a) use (&$connected, $connection) {
            $connected[] = $a->getEmail();
            return $connection;
        });
        $imap->method('isLegacyConfigured')->willReturn(false);
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getSpamFolder')->willReturn($this->createMock(MailboxInterface::class));

        $service = new RetroactiveSpamService($this->em, $this->scoring, $imap, $this->createMock(ConnectionService::class), $this->config,
            $inbox, $this->createMock(SshService::class), $this->createMock(AgentRulesExporter::class), $this->resolver);
        $result = $service->applyRule($rule);

        $this->assertSame([$strict->getEmail()], $connected);
        $this->assertStringContainsString('ola@firma.pl (10)', (string)$result['skipped']);

        // Too weak for every mailbox: the old one-line reason.
        $strict->setSpamThreshold(null);
        $this->em->flush();
        $connected = [];
        $this->assertSame('reguła ma 6 pkt, a próg spamu to 10', $service->applyRule($rule)['skipped']);
        $this->assertSame([], $connected);
    }

    public function testSshAgentApplyBlacklistGetsTheMailboxThreshold()
    {
        $ssh = $this->account('ssh@firma.pl', Account::CONNECTION_SSH)->setSpamThreshold(5)->setAgentDeployed(true);
        $this->em->flush();
        $rule = (new EmailBlacklist())->setEmail('ssh@firma.pl')->setBlacklistemail('x@evil.example')->setScore(5);
        $this->em->persist($rule);
        $this->em->flush();

        $agent = $this->createMock(SshService::class);
        $agent->method('syncRules')->willReturn(['success' => true]);
        $agent->expects($this->once())->method('applyBlacklist')->with($ssh, 5, RetroactiveSpamService::DAYS)->willReturn(['moved_to_spam' => 2]);
        $exporter = $this->createMock(AgentRulesExporter::class);
        $exporter->expects($this->once())->method('export')->with('ssh@firma.pl', $ssh)->willReturn([]);
        $imap = $this->createMock(ImapScanService::class);

        $service = new RetroactiveSpamService($this->em, $this->scoring, $imap, $this->createMock(ConnectionService::class), $this->config,
            $this->createMock(InboxService::class), $agent, $exporter, $this->resolver);
        $this->assertSame(2, $service->applyRule($rule)['moved']);
    }

    // --- quarantine digest ---------------------------------------------------

    private function quarantine(): QuarantineService
    {
        $q = $this->getMockBuilder(QuarantineService::class)
            ->setConstructorArgs([$this->em, $this->config, $this->createMock(SshService::class), $this->createMock(ConnectionService::class),
                $this->createMock(InboxService::class), $this->createMock(MessageService::class), $this->createMock(ImapScanService::class), $this->resolver])
            ->onlyMethods(['listItems'])
            ->getMock();
        $q->method('listItems')->willReturnCallback(fn ($key) => [[
            'id' => '1', 'from' => 'a@b.pl', 'from_name' => '', 'subject' => 'Oferta ' . $key, 'date' => new \DateTimeImmutable(), 'score' => 6, 'reasons' => [], 'uidvalidity' => 1,
        ]]);
        return $q;
    }

    private function digest(QuarantineService $q, array &$sent): QuarantineDigestService
    {
        $this->config->set('digest.from_email', 'antispam@firma.pl');
        $this->config->set('digest.base_url', 'https://antispam.firma.pl');
        $tokens = $this->createMock(DigestTokenService::class);
        $tokens->method('create')->willReturn('t');
        $twig = $this->createMock(Environment::class);
        $twig->method('render')->willReturn('x');
        $mailer = $this->createMock(MailerInterface::class);
        $mailer->method('send')->willReturnCallback(function (Email $m) use (&$sent) {
            $sent[] = $m->getTo()[0]->getAddress();
        });
        $router = $this->createMock(UrlGeneratorInterface::class);
        $router->method('generate')->willReturn('/q/t');
        return new QuarantineDigestService($q, $tokens, $twig, $mailer, $this->config, $router);
    }

    public function testDigestHonoursPerMailboxEnableAndRecipient()
    {
        $this->config->set('digest.enabled', true);
        $this->account('jan@firma.pl')->setDigestRecipient('kierownik@firma.pl');
        $this->account('ola@firma.pl')->setDigestEnabled(false);
        $this->account('ewa@firma.pl');
        $this->em->flush();
        $sent = [];
        $digest = $this->digest($this->quarantine(), $sent);

        $report = array_column($digest->sendAll(), 'status', 'recipient');
        $this->assertSame(['kierownik@firma.pl' => 'sent', 'ola@firma.pl' => 'disabled', 'ewa@firma.pl' => 'sent'], $report);
        $this->assertSame(['kierownik@firma.pl', 'ewa@firma.pl'], $sent);
    }

    public function testMailboxCanBeOnWhileTheGlobalDigestIsOff()
    {
        $this->config->set('digest.enabled', false);
        $this->account('jan@firma.pl')->setDigestEnabled(true);
        $this->account('ola@firma.pl');
        $this->em->flush();
        $sent = [];
        $digest = $this->digest($this->quarantine(), $sent);

        $this->assertTrue($digest->hasEnabledMailbox());
        $digest->sendAll();
        $this->assertSame(['jan@firma.pl'], $sent);

        // --force / "send now": inheriting mailboxes too, never one switched off.
        $this->account('off@firma.pl')->setDigestEnabled(false);
        $this->em->flush();
        $sent = [];
        $digest->sendAll(null, null, false, true, false, true);
        $this->assertSame(['jan@firma.pl', 'ola@firma.pl'], $sent);
    }

    public function testDigestHourDecidesWhenAMailboxIsDue()
    {
        $this->config->set('digest.enabled', true);
        $jan = $this->account('jan@firma.pl')->setDigestHour(14);
        $this->account('ola@firma.pl');
        $this->em->flush();
        $sent = [];
        $digest = $this->digest($this->quarantine(), $sent);
        $day = new \DateTimeImmutable('2026-10-28 00:00');

        // The daily run at 7:00: the inheriting mailbox goes, jan's hour has not come yet.
        $report = array_column($digest->sendAll(null, null, false, false, false, false, $day->setTime(7, 0)), 'status', 'recipient');
        $this->assertSame(['jan@firma.pl' => 'not-due', 'ola@firma.pl' => 'sent'], $report);

        // Hourly runs only look at mailboxes with their own hour.
        $sent = [];
        $this->assertSame([], $digest->sendAll(null, null, false, false, true, false, $day->setTime(13, 0)));
        $digest->sendAll(null, null, false, false, true, false, $day->setTime(14, 0));
        $this->assertSame(['jan@firma.pl'], $sent);

        // Sent today after 14:00 -> not again until tomorrow.
        $this->config->set('digest.last_sent.imap-' . $jan->getId(), (string)$day->setTime(14, 0, 5)->getTimestamp());
        $mailbox = $this->quarantine()->getMailbox('imap-' . $jan->getId());
        $this->assertFalse($digest->isDue($mailbox, $day->setTime(15, 0)));
        $this->assertTrue($digest->isDue($mailbox, $day->modify('+1 day')->setTime(14, 30)));
        $this->assertFalse($digest->isDue($mailbox, $day->modify('+1 day')->setTime(9, 0)));
    }

    public function testDigestRowsCarryTheMailboxSettings()
    {
        $jan = $this->account('jan@firma.pl')->setDigestRecipient('szef@firma.pl')->setDigestHour(9)->setDigestEnabled(true);
        $this->em->flush();
        $row = $this->quarantine()->getMailbox('imap-' . $jan->getId());
        $this->assertSame(['szef@firma.pl', true, 9], [$row['recipient'], $row['digest_enabled'], $row['digest_hour']]);
    }

    public function testAuditDetailsListTheOverrides()
    {
        $a = $this->account('jan@firma.pl');
        MailboxSettingsResolver::apply($a, $this->resolver->parseOverrides(['spam_threshold' => '7', 'digest_hour' => '6'])[0]);
        $this->assertSame(['spam_threshold' => 7, 'digest_hour' => 6], $a->getSettingsOverrides());
        $this->assertTrue($a->hasSettingsOverrides());
        $this->assertInstanceOf(MailboxSettings::class, $this->resolver->forAccount($a));
    }
}
