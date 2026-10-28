<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Entity\PhishingReport;
use AntispamBundle\Services\PhishingForwardService;
use AntispamBundle\Services\PhishingReportService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/** The forward UI renders: list badge + bulk button, detail panel (sent / not sent), settings form. */
class PhishingForwardTemplatesTest extends KernelTestCase
{
    private function render(string $template, array $vars): string
    {
        self::bootKernel();
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
        self::getContainer()->get('request_stack')->push($request);
        return self::getContainer()->get('twig')->render($template, $vars);
    }

    private function settings(): array
    {
        return ['recipients' => ['cert@cert.pl'], 'cc' => [], 'from_email' => '', 'from_name' => '', 'note' => '',
            'include_reporter' => false, 'max_kb' => 64, 'auto_minutes' => 0, 'auto_since' => null];
    }

    public function testDetailPage()
    {
        $raw = "From: a@evil.top\r\nSubject: Faktura\r\n\r\n" . str_repeat("x\r\n", 30000);
        $report = (new PhishingReport())->setRaw($raw)->setAccountEmail('jan@firma.pl')->setSubject('Faktura');
        (new \ReflectionProperty(PhishingReport::class, 'id'))->setValue($report, 7);
        $vars = [
            'report' => $report,
            'a' => (new PhishingReportService($this->createMock(EntityManagerInterface::class)))->analyze($report),
            'statuses' => PhishingReport::STATUSES,
            'sender_blocked' => false,
            'forwarded_before' => null,
            'forward_errors' => [],
            'forward_settings' => $this->settings(),
            'cert_form_url' => PhishingForwardService::CERT_FORM_URL,
        ];
        $html = $this->render('@Antispam/Phishing/show.html.twig', $vars);
        $this->assertStringContainsString('Wyślij do CERT Polska', $html);
        $this->assertStringContainsString('/phishing/7/forward', $html);
        $this->assertStringContainsString('pójdą tylko nagłówki', $html);
        $this->assertStringContainsString('https://incydent.cert.pl/', $html);

        $report->markForwarded(['cert@cert.pl'], new \DateTime('2026-10-01 10:00'));
        $html = $this->render('@Antispam/Phishing/show.html.twig', ['forwarded_before' => $report] + $vars);
        $this->assertStringContainsString('Wyślij ponownie', $html);
        $this->assertStringContainsString('name="resend" value="1"', $html);
        $this->assertStringContainsString('wysłano 2026-10-01 10:00', $html);
    }

    public function testListPage()
    {
        $html = $this->render('@Antispam/Phishing/index.html.twig', [
            'rows' => [[
                'id' => 3, 'createdAt' => new \DateTime(), 'lastReportedAt' => new \DateTime(), 'reportCount' => 1,
                'accountEmail' => 'jan@firma.pl', 'client' => 'outlook', 'sender' => 'a@evil.top', 'senderName' => null,
                'replyTo' => null, 'subject' => 'Faktura', 'size' => 10, 'truncated' => false, 'status' => 'reported',
                'sha256' => str_repeat('a', 64), 'forwardedAt' => new \DateTime('2026-10-01 10:00'), 'forwardedTo' => 'cert@cert.pl', 'forwardError' => null,
            ]],
            'total' => 1, 'page' => 1, 'pages' => 1, 'filters' => ['status' => null, 'account' => null, 'q' => ''], 'query' => [],
            'accounts' => ['jan@firma.pl'], 'counts' => array_fill_keys(array_keys(PhishingReport::STATUSES), 0),
            'statuses' => PhishingReport::STATUSES, 'forward_errors' => [], 'forward_recipients' => ['cert@cert.pl'],
            'cert_form_url' => PhishingForwardService::CERT_FORM_URL,
        ]);
        $this->assertStringContainsString('Wyślij zaznaczone do CERT Polska', $html);
        $this->assertStringContainsString('wysłano 2026-10-01 10:00', $html);
        $this->assertMatchesRegularExpression('/value="3" form="phishing-bulk"[^>]*disabled/', $html);
    }

    public function testSettingsPage()
    {
        $html = $this->render('@Antispam/Phishing/forward_settings.html.twig', [
            'settings' => $this->settings(), 'errors' => [], 'status_errors' => [],
            'default_recipient' => PhishingForwardService::DEFAULT_RECIPIENT, 'default_note' => PhishingForwardService::DEFAULT_NOTE,
            'cert_form_url' => PhishingForwardService::CERT_FORM_URL,
        ]);
        $this->assertStringContainsString('value="cert@cert.pl"', $html);
        $this->assertStringContainsString('name="config[include_reporter]"', $html);
    }
}
