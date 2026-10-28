<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Config;
use AntispamBundle\Entity\PhishingReport;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\PhishingForwardService;
use AntispamBundle\Services\PhishingReportService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Part\DataPart;
use Symfony\Component\Mime\RawMessage;

/**
 * One-click forward of a phishing report to CERT Polska / SOC: recipients,
 * attachment (unmodified message/rfc822), privacy of the reporter address,
 * double-send guard, size limit / truncated notice, settings validation and
 * the automatic mode. Runs against an in-memory SQLite database so the
 * repository queries (claim, copy lookup, candidates) are exercised for real.
 */
class PhishingForwardServiceTest extends TestCase
{
    private const RAW = "From: \"PKO BP\" <alert@pko-bp.top>\r\n"
        . "To: jan@firma.pl\r\n"
        . "Reply-To: zwrot@evil.top\r\n"
        . "Subject: Zablokowane konto\r\n"
        . "Authentication-Results: mx.firma.pl; spf=fail smtp.mailfrom=pko-bp.top; dmarc=fail header.from=pko-bp.top\r\n"
        . "Content-Type: text/html; charset=UTF-8\r\n"
        . "\r\n"
        . "<p>Zaloguj się: <a href=\"https://login.evil.top/pl\">https://www.pkobp.pl/</a> - zażółć</p>\r\n";

    private EntityManager $em;
    private ConfigService $config;
    /** @var RawMessage[] */
    private array $sent = [];
    private ?\Throwable $failWith = null;

    protected function setUp(): void
    {
        $setup = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $setup);
        (new SchemaTool($this->em))->createSchema([
            $this->em->getClassMetadata(Config::class),
            $this->em->getClassMetadata(PhishingReport::class),
        ]);
        $this->config = new ConfigService($this->em);
        $this->config->set('digest.from_email', 'antispam@firma.pl');
        $this->sent = [];
        $this->failWith = null;
    }

    private function service(): PhishingForwardService
    {
        $test = $this;
        $mailer = new class($test) implements MailerInterface {
            public function __construct(private PhishingForwardServiceTest $test) {}
            public function send(RawMessage $message, ?Envelope $envelope = null): void
            {
                $this->test->recordSend($message);
            }
        };
        return new PhishingForwardService($this->config, $mailer, $this->em, new PhishingReportService($this->em));
    }

    /** @internal called by the test mailer */
    public function recordSend(RawMessage $message): void
    {
        if ($this->failWith) {
            throw $this->failWith;
        }
        $this->sent[] = $message;
    }

    private function report(string $raw = self::RAW, string $account = 'jan@firma.pl', ?\DateTime $createdAt = null): PhishingReport
    {
        $r = (new PhishingReport())->setRaw($raw)->setAccountEmail($account)
            ->setSender('alert@pko-bp.top')->setSenderName('PKO BP')->setReplyTo('zwrot@evil.top')->setSubject('Zablokowane konto');
        if ($createdAt) {
            (new \ReflectionProperty(PhishingReport::class, 'createdAt'))->setValue($r, $createdAt);
        }
        $this->em->persist($r);
        $this->em->flush();
        return $r;
    }

    private function attachment(Email $email): DataPart
    {
        $this->assertCount(1, $email->getAttachments());
        return $email->getAttachments()[0];
    }

    public function testDefaultRecipientIsCertPolska()
    {
        $this->assertSame(['cert@cert.pl'], $this->service()->getSettings()['recipients']);
        $this->assertSame([], $this->service()->configurationErrors());
    }

    public function testForwardSendsOriginalAsRfc822AttachmentToCert()
    {
        $report = $this->report();
        $result = $this->service()->forward($report);

        $this->assertSame('sent', $result['status']);
        $this->assertCount(1, $this->sent);
        /** @var Email $email */
        $email = $this->sent[0];
        $this->assertSame(['cert@cert.pl'], array_map(fn($a) => $a->getAddress(), $email->getTo()));
        $this->assertSame('antispam@firma.pl', $email->getFrom()[0]->getAddress());
        $this->assertSame('Phishing: Zablokowane konto', $email->getSubject());

        $part = $this->attachment($email);
        $this->assertSame('message/rfc822', $part->getMediaType() . '/' . $part->getMediaSubtype());
        $this->assertSame(self::RAW, $part->getBody(), 'the original must be attached byte for byte');
        $this->assertStringContainsString('Content-Transfer-Encoding: 8bit', $part->toString());
        $this->assertStringContainsString(self::RAW, $email->toString(), 'serialized without re-encoding');

        $text = $email->getTextBody();
        $this->assertStringContainsString('zwrot@evil.top', $text);
        $this->assertStringContainsString('SPF=fail', $text);
        $this->assertStringContainsString('login.evil.top', $text);
        $this->assertStringNotContainsString('jan@firma.pl', $text, 'reporter address is off by default');

        $this->em->clear();
        $stored = $this->em->find(PhishingReport::class, $report->getId());
        $this->assertNotNull($stored->getForwardedAt());
        $this->assertSame('cert@cert.pl', $stored->getForwardedTo());
        $this->assertNull($stored->getForwardError());
        $this->assertSame(PhishingReport::STATUS_REPORTED, $stored->getStatus());
    }

    public function testCcAndReporterAddressWhenEnabled()
    {
        $s = $this->service();
        [$in, $errors] = $s->validateSettings([
            'recipients' => 'soc@firma.pl; cert@cert.pl', 'cc' => 'admin@firma.pl', 'from_email' => 'phish@firma.pl',
            'from_name' => "Antispam\r\nBcc: x@y.pl", 'include_reporter' => '1', 'max_kb' => '2048', 'note' => 'Zgłoszenie {id}',
        ]);
        $this->assertSame([], $errors);
        $this->assertSame('Antispam Bcc: x@y.pl', $in['from_name'], 'no header injection through the name');
        $s->saveSettings($in);

        $report = $this->report();
        $this->assertSame('sent', $s->forward($report)['status']);
        $email = $this->sent[0];
        $this->assertSame(['soc@firma.pl', 'cert@cert.pl'], array_map(fn($a) => $a->getAddress(), $email->getTo()));
        $this->assertSame(['admin@firma.pl'], array_map(fn($a) => $a->getAddress(), $email->getCc()));
        $this->assertSame('phish@firma.pl', $email->getFrom()[0]->getAddress());
        $this->assertStringStartsWith('Zgłoszenie ' . $report->getId(), $email->getTextBody());
        $this->assertStringContainsString('przez skrzynkę jan@firma.pl', $email->getTextBody());
        $this->assertSame('soc@firma.pl, cert@cert.pl, admin@firma.pl', $report->getForwardedTo());
    }

    public function testSecondSendIsRefusedUnlessConfirmed()
    {
        $report = $this->report();
        $s = $this->service();
        $this->assertSame('sent', $s->forward($report)['status']);

        $again = $s->forward($report);
        $this->assertSame('skipped', $again['status']);
        $this->assertCount(1, $this->sent);

        $this->assertSame('sent', $s->forward($report, true)['status'], 'explicit resend is allowed');
        $this->assertCount(2, $this->sent);
    }

    public function testCopyFromAnotherMailboxCountsAsAlreadySent()
    {
        $first = $this->report(self::RAW, 'jan@firma.pl');
        $copy = $this->report(self::RAW, 'anna@firma.pl');
        $s = $this->service();
        $s->forward($first);

        $this->assertSame($first->getId(), $s->previouslyForwarded($copy)->getId());
        $this->assertSame('skipped', $s->forward($copy)['status']);
        $this->assertCount(1, $this->sent);
    }

    public function testParallelAttemptIsBlockedByClaim()
    {
        $report = $this->report();
        // Another request claimed it a moment ago and is still sending.
        $this->assertTrue($this->em->getRepository(PhishingReport::class)
            ->claimForForward($report->getId(), new \DateTime(), new \DateTime('-10 minutes')));

        $this->assertSame('skipped', $this->service()->forward($report)['status']);
        $this->assertSame([], $this->sent);
    }

    public function testFalsePositiveIsNeverSent()
    {
        $report = $this->report()->setStatus(PhishingReport::STATUS_FALSE_POSITIVE);
        $this->em->flush();
        $this->assertSame('skipped', $this->service()->forward($report)['status']);
        $this->assertSame([], $this->sent);
    }

    public function testTransportErrorIsRecordedAndRetryAllowed()
    {
        $report = $this->report();
        $this->failWith = new TransportException('Connection refused');
        $result = $this->service()->forward($report);

        $this->assertSame('failed', $result['status']);
        $this->assertSame('Connection refused', $report->getForwardError());
        $this->assertNull($report->getForwardedAt());
        $this->assertSame(PhishingReport::STATUS_NEW, $report->getStatus());

        $this->failWith = null;
        $this->assertSame('sent', $this->service()->forward($report)['status'], 'a failed attempt can be retried at once');
    }

    public function testTooBigMessageGoesAsHeadersWithNotice()
    {
        $this->config->set('phishing_forward.max_kb', '64');
        $raw = self::RAW . str_repeat("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n", 1100);
        $email = $this->service()->buildEmail($this->report($raw));

        $part = $this->attachment($email);
        $this->assertSame('text/rfc822-headers', $part->getMediaType() . '/' . $part->getMediaSubtype());
        $this->assertStringContainsString('Subject: Zablokowane konto', $part->getBody());
        $this->assertStringNotContainsString('AAAA', $part->getBody());
        $this->assertStringContainsString('przekracza limit 64 KiB', $email->getTextBody());
    }

    public function testTruncatedSourceIsSentWithNotice()
    {
        $report = $this->report()->setTruncated(true);
        $email = $this->service()->buildEmail($report);

        $this->assertSame(self::RAW, $this->attachment($email)->getBody());
        $this->assertStringContainsString('obcięł', $email->getTextBody());
    }

    public function testOverlongLinesFallBackToBase64WithoutChangingContent()
    {
        $raw = "Subject: x\r\n\r\n" . str_repeat('x', 2000) . "\r\n";
        $part = $this->attachment($this->service()->buildEmail($this->report($raw)));
        $this->assertStringContainsString('Content-Transfer-Encoding: base64', $part->toString());
        $this->assertSame($raw, $part->getBody());
    }

    public function testSettingsValidation()
    {
        [, $errors] = $this->service()->validateSettings([
            'recipients' => 'cert@cert.pl, nie-adres', 'cc' => 'admin@', 'from_email' => 'x@', 'max_kb' => '5', 'auto_minutes' => '-1',
        ]);
        $this->assertCount(5, $errors);
        $this->assertStringContainsString('nie-adres', $errors[0]);

        [$ok, $errors] = $this->service()->validateSettings(['recipients' => '', 'max_kb' => '1024']);
        $this->assertSame([], $errors, 'an empty recipient list is allowed (disables forwarding)');
        $this->assertSame([], $ok['recipients']);

        [, $errors] = $this->service()->validateSettings(['recipients' => '', 'max_kb' => '1024', 'auto_minutes' => '30']);
        $this->assertNotEmpty($errors, 'automatic mode needs a recipient');
    }

    public function testClearedRecipientsDisableForwarding()
    {
        $s = $this->service();
        [$in] = $s->validateSettings(['recipients' => '', 'max_kb' => '1024']);
        $s->saveSettings($in);
        $this->assertNotEmpty($s->configurationErrors());
        $this->assertSame('skipped', $s->forward($this->report())['status']);
        $this->assertSame([], $this->sent);
    }

    public function testAutomaticModeIsOffByDefault()
    {
        $this->report(self::RAW, 'jan@firma.pl', new \DateTime('-2 days'));
        $this->assertSame([], $this->service()->forwardPending());
        $this->assertSame([], $this->sent);
    }

    public function testAutomaticModeSendsOnlyNewEnoughOldEnoughReportsOnce()
    {
        $s = $this->service();
        $backlog = $this->report("Subject: stare\r\n\r\nx\r\n", 'jan@firma.pl', new \DateTime('-2 days'));
        [$in] = $s->validateSettings(['recipients' => 'cert@cert.pl', 'max_kb' => '1024', 'auto_minutes' => '30']);
        $s->saveSettings($in);
        // Pretend the mode was switched on an hour ago.
        $this->config->set('phishing_forward.auto_since', (new \DateTime('-1 hour'))->format('Y-m-d H:i:s'));

        $due = $this->report(self::RAW, 'jan@firma.pl', new \DateTime('-40 minutes'));
        $dueCopy = $this->report(self::RAW, 'anna@firma.pl', new \DateTime('-39 minutes'));
        $fp = $this->report("Subject: fp\r\n\r\nx\r\n", 'jan@firma.pl', new \DateTime('-40 minutes'))->setStatus(PhishingReport::STATUS_FALSE_POSITIVE);
        $fresh = $this->report("Subject: nowe\r\n\r\nx\r\n", 'jan@firma.pl', new \DateTime('-5 minutes'));
        $this->em->flush();

        $results = $s->forwardPending();
        $this->assertSame('sent', $results[$due->getId()]['status']);
        $this->assertSame('skipped', $results[$dueCopy->getId()]['status']);
        $this->assertArrayNotHasKey($backlog->getId(), $results, 'backlog from before the switch is not mass-sent');
        $this->assertArrayNotHasKey($fp->getId(), $results);
        $this->assertArrayNotHasKey($fresh->getId(), $results, 'admin still has time to review');
        $this->assertCount(1, $this->sent);

        $this->assertSame([], $s->forwardPending(), 'nothing is sent twice');
    }

    public function testNullMailerTransportIsNotReportedAsSent()
    {
        $mailer = $this->createMock(MailerInterface::class);
        $mailer->expects($this->never())->method('send');
        foreach (['null://null', ''] as $dsn) {
            $s = new PhishingForwardService($this->config, $mailer, $this->em, new PhishingReportService($this->em), null, $dsn);
            $this->assertNotEmpty($s->configurationErrors(), $dsn);
            $this->assertSame('skipped', $s->forward($this->report())['status']);
        }
        $ok = new PhishingForwardService($this->config, $mailer, $this->em, new PhishingReportService($this->em), null, 'smtp://mail.firma.pl:587');
        $this->assertSame([], $ok->configurationErrors());
    }

    public function testSubjectIsSingleLine()
    {
        $r = (new PhishingReport())->setSubject("Pilne\r\n  konto");
        $this->assertSame('Phishing: Pilne konto', PhishingForwardService::subjectFor($r));
        $this->assertSame('Phishing: (bez tematu)', PhishingForwardService::subjectFor(new PhishingReport()));
    }
}
