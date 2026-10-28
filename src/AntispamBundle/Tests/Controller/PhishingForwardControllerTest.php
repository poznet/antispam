<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\PhishingController;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\Config;
use AntispamBundle\Entity\PhishingReport;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\PhishingForwardService;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\Jobs\Handler\PhishingForwardHandler;
use AntispamBundle\Services\Jobs\JobQueue;
use AntispamBundle\Services\ScoringService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\RawMessage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * "Wyślij do CERT Polska": POST + CSRF, admin-only path, confirmation needed
 * for a second send, bulk action skipping already sent reports, and the
 * settings form refusing invalid addresses.
 */
class PhishingForwardControllerTest extends TestCase
{
    private EntityManager $em;
    private Session $session;
    public array $sent = [];

    protected function setUp(): void
    {
        $setup = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $setup);
        (new SchemaTool($this->em))->createSchema([
            $this->em->getClassMetadata(Config::class),
            $this->em->getClassMetadata(PhishingReport::class),
            $this->em->getClassMetadata(BackgroundJob::class),
        ]);
        $this->sent = [];
    }

    private PhishingForwardService $forwarder;

    private function controller(): PhishingController
    {
        $config = new ConfigService($this->em);
        $config->set('digest.from_email', 'antispam@firma.pl');
        $test = $this;
        $mailer = new class($test) implements MailerInterface {
            public function __construct(private PhishingForwardControllerTest $test) {}
            public function send(RawMessage $message, ?Envelope $envelope = null): void
            {
                $this->test->sent[] = $message;
            }
        };
        $forwarder = new PhishingForwardService($config, $mailer, $this->em, new PhishingReportService($this->em));
        $this->forwarder = $forwarder;
        $controller = new PhishingController($this->em, new PhishingReportService($this->em),
            $this->createMock(DeferredRetroactivePass::class), $this->createMock(ScoringService::class), $forwarder,
            new JobQueue($this->em->getConnection(), $this->em));

        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturnCallback(fn(CsrfToken $t) => in_array($t->getId(), ['phishing', 'phishing_forward_settings'], true) && $t->getValue() === 'good');
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(fn($name) => '/' . $name);
        $this->session = new Session(new MockArraySessionStorage());
        $request = new Request();
        $request->setSession($this->session);
        $stack = new RequestStack();
        $stack->push($request);
        $controller->setContainer(new ServiceLocator([
            'security.csrf.token_manager' => fn() => $csrf,
            'router' => fn() => $router,
            'request_stack' => fn() => $stack,
        ]));
        return $controller;
    }

    private function report(string $account = 'jan@firma.pl'): PhishingReport
    {
        $r = (new PhishingReport())->setRaw("From: a@evil.top\r\nSubject: Faktura\r\n\r\nzapłać\r\n")
            ->setAccountEmail($account)->setSender('a@evil.top')->setSubject('Faktura');
        $this->em->persist($r);
        $this->em->flush();
        return $r;
    }

    public function testForwardRequiresCsrfToken()
    {
        $report = $this->report();
        $controller = $this->controller();
        foreach ([[], ['_token' => 'bad']] as $data) {
            try {
                $controller->forwardAction($report->getId(), Request::create('/x', 'POST', $data));
                $this->fail('forward without a valid CSRF token must be refused');
            } catch (AccessDeniedException) {
            }
        }
        $this->assertSame([], $this->sent);
        $this->assertNull($report->getForwardedAt());
    }

    public function testForwardSendsOnceThenAsksForConfirmation()
    {
        $report = $this->report();
        $controller = $this->controller();

        $controller->forwardAction($report->getId(), Request::create('/x', 'POST', ['_token' => 'good']));
        $this->assertCount(1, $this->sent);
        $this->assertNotEmpty($this->session->getFlashBag()->get('success'));

        // Double click / back button: refused with a warning, nothing sent.
        $controller->forwardAction($report->getId(), Request::create('/x', 'POST', ['_token' => 'good']));
        $this->assertCount(1, $this->sent);
        $this->assertStringContainsString('już wysłana', $this->session->getFlashBag()->get('warning')[0]);

        // Confirmed resend.
        $controller->forwardAction($report->getId(), Request::create('/x', 'POST', ['_token' => 'good', 'resend' => '1']));
        $this->assertCount(2, $this->sent);
    }

    public function testBulkSkipsAlreadySentAndDuplicateMessages()
    {
        $a = $this->report('jan@firma.pl');
        $copy = $this->report('anna@firma.pl'); // same message, another mailbox
        $b = (new PhishingReport())->setRaw("Subject: inna\r\n\r\nx\r\n")->setAccountEmail('jan@firma.pl');
        $this->em->persist($b);
        $this->em->flush();

        $controller = $this->controller();
        $response = $controller->forwardBulkAction(Request::create('/x', 'POST', ['_token' => 'good', 'ids' => [$a->getId(), $copy->getId(), $b->getId()]]));
        $this->assertSame('/antispam_job_show', $response->getTargetUrl(), 'the request only queues the e-mails');
        $this->assertSame([], $this->sent);
        $this->assertNotEmpty($this->session->getFlashBag()->get('success'));

        $this->assertSame(['counts' => ['sent' => 2, 'failed' => 0, 'skipped' => 1], 'errors' => []], $this->runJobs());
        $this->assertCount(2, $this->sent);

        $controller->forwardBulkAction(Request::create('/x', 'POST', ['_token' => 'good', 'ids' => [$a->getId(), $b->getId()]]));
        $this->runJobs();
        $this->assertCount(2, $this->sent, 'bulk never resends');
    }

    /** Runs the newest queued job (the bulk forward) with its handler, returns the result. */
    private function runJobs(): array
    {
        $db = $this->em->getConnection();
        $row = $db->fetchAssociative('SELECT * FROM antispam_job ORDER BY id DESC LIMIT 1');
        $this->assertSame(BackgroundJob::TYPE_PHISHING_FORWARD, $row['type']);
        $context = new \AntispamBundle\Services\Jobs\JobContext($db, (int)$row['id'], $row['type'], json_decode($row['payload'], true), [], null, null, null, null, microtime(true) + 60);
        return (new PhishingForwardHandler($this->em, $this->forwarder))->handle($context);
    }

    public function testBulkRequiresCsrfToken()
    {
        $this->expectException(AccessDeniedException::class);
        $this->controller()->forwardBulkAction(Request::create('/x', 'POST', ['ids' => [$this->report()->getId()]]));
    }

    public function testSettingsRejectInvalidAddressesAndKeepDefaults()
    {
        $controller = $this->controller();
        $view = $controller->forwardSettingsAction(Request::create('/x', 'POST', ['_token' => 'good', 'config' => [
            'recipients' => 'cert@cert.pl, zły adres@', 'cc' => '', 'from_email' => '', 'max_kb' => '10240', 'auto_minutes' => '0',
        ]]));
        $this->assertIsArray($view, 'invalid input re-renders the form');
        $this->assertNotEmpty($view['errors']);
        $this->assertNull((new ConfigService($this->em))->get('phishing_forward.recipients'), 'nothing saved');

        $this->expectException(AccessDeniedException::class);
        $controller->forwardSettingsAction(Request::create('/x', 'POST', ['config' => ['recipients' => 'soc@firma.pl']]));
    }

    public function testSettingsSave()
    {
        $response = $this->controller()->forwardSettingsAction(Request::create('/x', 'POST', ['_token' => 'good', 'config' => [
            'recipients' => 'soc@firma.pl', 'cc' => 'admin@firma.pl', 'from_email' => 'phish@firma.pl', 'max_kb' => '4096', 'auto_minutes' => '0',
        ]]));
        $this->assertSame(302, $response->getStatusCode());
        $this->assertSame('soc@firma.pl', (new ConfigService($this->em))->get('phishing_forward.recipients'));
    }
}
