<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\AccountController;
use AntispamBundle\Controller\CertController;
use AntispamBundle\Controller\JobController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\ImapTlsProbe;
use AntispamBundle\Services\MailboxSettingsResolver;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SshService;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Heavy panel buttons queue a background job and redirect to its page - the
 * IMAP / SSH work never runs in the request (it used to end in a 504).
 */
class JobControllersTest extends TestCase
{
    private JobsDatabase $db;
    private Session $session;
    /** @var string[] generated routes */
    private array $routes = [];

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
    }

    private function wire(AbstractController $controller): AbstractController
    {
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturnCallback(fn(CsrfToken $t) => $t->getValue() === 'good');
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(function ($name, $params = []) {
            $this->routes[] = $name;
            return '/' . $name . ($params ? '/' . implode('/', $params) : '');
        });
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

    private function accounts(?SshService $ssh = null, ?ImapScanService $imap = null): AccountController
    {
        $ssh ??= $this->createMock(SshService::class);
        $imap ??= $this->createMock(ImapScanService::class);
        return $this->wire(new AccountController($this->db->em, $ssh, $this->db->queue, $imap, $this->createMock(CryptoService::class),
            $this->createMock(ImapTlsProbe::class), $this->createMock(ConfigService::class), $this->createMock(MailboxSettingsResolver::class)));
    }

    private function account(string $type = Account::CONNECTION_IMAP, bool $deployed = false): Account
    {
        $a = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType($type)->setAgentDeployed($deployed);
        $this->db->em->persist($a);
        $this->db->em->flush();
        return $a;
    }

    private static function post(array $data = ['_token' => 'good']): Request
    {
        return Request::create('/x', 'POST', $data);
    }

    public function testScanIsQueuedNotRunAndASecondClickReusesTheJob()
    {
        $account = $this->account();
        $imap = $this->createMock(ImapScanService::class);
        $imap->expects($this->never())->method('scanAccount');
        $imap->expects($this->never())->method('connect');
        $controller = $this->accounts(null, $imap);

        $response = $controller->scanAction($account->getId(), self::post());
        $this->assertSame('/antispam_job_show/1', $response->getTargetUrl());
        $row = $this->db->row(1);
        $this->assertSame([BackgroundJob::TYPE_ACCOUNT_SCAN, 'queued', (string)$account->getId(), 'jan@firma.pl'], [$row['type'], $row['status'], (string)$row['account_id'], $row['mailbox']]);
        $this->assertStringContainsString('dodane do kolejki', $this->session->getFlashBag()->get('success')[0]);

        $response = $controller->scanAction($account->getId(), self::post());
        $this->assertSame('/antispam_job_show/1', $response->getTargetUrl());
        $this->assertStringContainsString('już w kolejce', $this->session->getFlashBag()->get('info')[0]);
        $this->assertSame(1, (int)$this->db->em->getConnection()->fetchOne('SELECT COUNT(*) FROM antispam_job'));
    }

    public function testSshButtonsQueueTheirJobs()
    {
        $account = $this->account(Account::CONNECTION_SSH, true);
        $ssh = $this->createMock(SshService::class);
        foreach (['deployAgent', 'syncRules', 'runHealth', 'runScan'] as $m) {
            $ssh->expects($this->never())->method($m);
        }
        $controller = $this->accounts($ssh);
        $controller->deployAction($account->getId(), self::post());
        $controller->syncAction($account->getId(), self::post());
        $controller->healthAction($account->getId(), self::post());
        $controller->scanAction($account->getId(), self::post());

        $types = $this->db->em->getConnection()->fetchFirstColumn('SELECT type FROM antispam_job ORDER BY id');
        $this->assertSame([BackgroundJob::TYPE_ACCOUNT_DEPLOY, BackgroundJob::TYPE_ACCOUNT_SYNC, BackgroundJob::TYPE_ACCOUNT_HEALTH, BackgroundJob::TYPE_ACCOUNT_SCAN], $types);
    }

    public function testRefusalsDoNotQueue()
    {
        $imapAccount = $this->account();
        $controller = $this->accounts();
        $controller->deployAction($imapAccount->getId(), self::post());
        $this->assertNotEmpty($this->session->getFlashBag()->get('danger'), 'deploy is for SSH accounts');

        $ssh = $this->account(Account::CONNECTION_SSH, false);
        $controller->scanAction($ssh->getId(), self::post());
        $this->assertStringContainsString('Wdróż', $this->session->getFlashBag()->get('warning')[0]);

        try {
            $controller->scanAction($imapAccount->getId(), self::post(['_token' => 'bad']));
            $this->fail('CSRF');
        } catch (AccessDeniedException) {
        }
        $this->assertSame(0, (int)$this->db->em->getConnection()->fetchOne('SELECT COUNT(*) FROM antispam_job'));
    }

    public function testAccountListShowsActiveJobs()
    {
        $account = $this->account();
        $this->accounts()->scanAction($account->getId(), self::post());
        $view = $this->accounts()->indexAction();
        $this->assertSame(BackgroundJob::TYPE_ACCOUNT_SCAN, $view['active_jobs'][$account->getId()][0]['type']);
    }

    public function testCertSyncIsQueued()
    {
        $cert = $this->createMock(CertHoleService::class);
        $cert->expects($this->never())->method('sync');
        $controller = $this->wire(new CertController($this->db->em, $cert, $this->createMock(ConfigService::class), $this->createMock(ScoringService::class), $this->db->queue));
        $this->assertSame('/antispam_job_show/1', $controller->syncAction(self::post())->getTargetUrl());
        $this->assertSame(BackgroundJob::TYPE_CERT_SYNC, $this->db->row(1)['type']);
    }

    public function testStatusJsonAndCancel()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, label: 'Skanowanie: Jan')->id;
        $this->db->update($id, ['status' => 'running', 'progress' => 'Przetworzono 10 wiadomości, zostało 30', 'progress_done' => 10, 'progress_total' => 40]);
        $controller = $this->wire(new JobController($this->db->em, $this->db->queue));

        $json = json_decode($controller->statusAction($id)->getContent(), true);
        $this->assertSame(['running', false, 25, 'Przetworzono 10 wiadomości, zostało 30'], [$json['status'], $json['finished'], $json['percent'], $json['progress']]);

        try {
            $controller->cancelAction($id, self::post(['_token' => 'bad']));
            $this->fail('CSRF');
        } catch (AccessDeniedException) {
        }
        $controller->cancelAction($id, self::post());
        $this->assertTrue(json_decode($controller->statusAction($id)->getContent(), true)['cancel_requested']);

        $view = $controller->showAction($id);
        $this->assertSame($id, $view['job']->getId());
        $list = $controller->indexAction(Request::create('/jobs/', 'GET', ['status' => 'active']));
        $this->assertCount(1, $list['jobs']);
    }
}
