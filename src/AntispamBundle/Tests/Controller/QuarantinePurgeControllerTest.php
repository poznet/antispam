<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\MyController;
use AntispamBundle\Controller\SpamboxController;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\QuarantinePurge;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\SpamFolderService;
use AntispamBundle\Tests\Security\MailboxAccessTest;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * The bulk quarantine delete buttons only queue a background job
 * (quarantine.purge): nothing is deleted in the request. A user may only purge
 * - and only see the job page of - their own mailbox.
 */
class QuarantinePurgeControllerTest extends TestCase
{
    private JobsDatabase $db;
    private Session $session;
    /** @var QuarantineService&MockObject */
    private $quarantine;

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
        $this->quarantine = $this->createMock(QuarantineService::class);
        $this->quarantine->expects($this->never())->method('purge');
        $this->quarantine->expects($this->never())->method('delete');
        $mailboxes = [
            ['key' => 'imap-5', 'label' => 'Jan (jan@firma.pl)', 'account_email' => 'jan@firma.pl'],
            ['key' => 'ssh-6', 'label' => 'Ola (ola@firma.pl)', 'account_email' => 'ola@firma.pl'],
            ['key' => 'imap', 'label' => 'IMAP: biuro@firma.pl', 'account_email' => 'biuro@firma.pl'],
        ];
        $this->quarantine->method('getMailboxes')->willReturn($mailboxes);
        $this->quarantine->method('getMailbox')->willReturnCallback(function ($key) use ($mailboxes) {
            foreach ($mailboxes as $m) {
                if ($m['key'] === $key) {
                    return $m;
                }
            }
            return null;
        });
    }

    private function wire(AbstractController $controller, ?User $user = null): AbstractController
    {
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturnCallback(fn(CsrfToken $t) => $t->getValue() === 'good');
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(fn($name, $params = []) => '/' . $name . ($params ? '/' . implode('/', $params) : ''));
        $this->session = new Session(new MockArraySessionStorage());
        $request = new Request();
        $request->setSession($this->session);
        $stack = new RequestStack();
        $stack->push($request);
        $tokens = new TokenStorage();
        if ($user) {
            $tokens->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        }
        $controller->setContainer(new ServiceLocator([
            'security.csrf.token_manager' => fn() => $csrf,
            'router' => fn() => $router,
            'request_stack' => fn() => $stack,
            'security.token_storage' => fn() => $tokens,
        ]));
        return $controller;
    }

    private function purger(): QuarantinePurge
    {
        return new QuarantinePurge($this->db->queue, $this->db->em);
    }

    private function my(User $user): MyController
    {
        return $this->wire(new MyController($this->db->em, $this->quarantine, new MailboxAccess(), $this->createMock(UserPasswordHasherInterface::class),
            $this->createMock(SpamFolderService::class), $this->createMock(DeferredAgentSync::class), $this->purger(), $this->db->queue), $user);
    }

    private function spambox(): SpamboxController
    {
        return $this->wire(new SpamboxController($this->db->em, $this->createMock(InboxService::class), $this->createMock(ConnectionService::class),
            $this->quarantine, $this->createMock(MessageService::class), null, $this->purger()));
    }

    private static function user(string $name, string $role = User::ROLE_USER): User
    {
        return MailboxAccessTest::user($role, [MailboxAccessTest::account(5, 'jan@firma.pl')])->setUsername($name);
    }

    private static function post(array $data): Request
    {
        return Request::create('/x', 'POST', $data + ['_token' => 'good']);
    }

    private function jobCount(): int
    {
        return (int)$this->db->em->getConnection()->fetchOne('SELECT COUNT(*) FROM ' . BackgroundJob::TABLE);
    }

    public function testUserCannotPurgeSomeoneElsesMailbox()
    {
        $controller = $this->my(self::user('jan'));
        foreach (['ssh-6', 'imap-6', 'ssh-5', 'imap', ''] as $key) {
            try {
                $controller->quarantinePurgeAction(self::post(['mailbox' => $key, 'mode' => 'all']));
                $this->fail('purge of ' . $key . ' must be forbidden');
            } catch (AccessDeniedException) {
            }
        }
        $this->assertSame(0, $this->jobCount());
    }

    public function testUserQueuesAPurgeOfTheOwnMailboxAndSeesItsJob()
    {
        $controller = $this->my(self::user('jan'));
        $response = $controller->quarantinePurgeAction(self::post(['mailbox' => 'imap-5', 'mode' => 'high_risk', 'shown' => '4']));

        $this->assertSame('/antispam_my_job_show/1', $response->getTargetUrl());
        $row = $this->db->row(1);
        $this->assertSame([BackgroundJob::TYPE_QUARANTINE_PURGE, 'queued', 'jan', 'user', 'jan@firma.pl'], [$row['type'], $row['status'], $row['requested_by'], $row['requested_by_type'], $row['mailbox']]);
        $this->assertSame(['key' => 'imap-5', 'mode' => 'high_risk', 'source' => 'my', 'shown' => 4], json_decode($row['payload'], true));
        $this->assertStringContainsString('dodane do kolejki', $this->session->getFlashBag()->get('success')[0]);

        $this->assertSame(1, $controller->jobAction(1)['job']->getId());
        $this->assertSame('queued', json_decode($controller->jobStatusAction(1)->getContent(), true)['status']);
    }

    public function testBadTokenOrModeQueuesNothing()
    {
        $controller = $this->my(self::user('jan'));
        $controller->quarantinePurgeAction(Request::create('/x', 'POST', ['_token' => 'bad', 'mailbox' => 'imap-5', 'mode' => 'all']));
        $controller->quarantinePurgeAction(self::post(['mailbox' => 'imap-5', 'mode' => 'everything']));
        $this->spambox()->quarantinePurgeAction(Request::create('/x', 'POST', ['_token' => 'bad', 'mailbox' => 'imap-5', 'mode' => 'all']));
        $this->spambox()->quarantinePurgeAllAction(Request::create('/x', 'POST', ['_token' => 'bad']));
        $this->assertSame(0, $this->jobCount());
    }

    public function testUserSeesOnlyOwnPurgeJobs()
    {
        $this->my(self::user('jan'))->quarantinePurgeAction(self::post(['mailbox' => 'imap-5', 'mode' => 'all']));
        // Another user sharing the mailbox, an admin's purge of it, and an unrelated job.
        $adminJob = $this->purger()->enqueue($this->quarantine->getMailbox('imap-5'), 'high_risk', QuarantinePurge::SOURCE_PANEL)->id;
        $scanJob = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, [], null, 'scan', 'x')->id;

        $ewa = $this->my(self::user('ewa'));
        foreach ([1, $adminJob, $scanJob, 999] as $id) {
            try {
                $ewa->jobAction($id);
                $this->fail('job ' . $id . ' must not be visible to ewa');
            } catch (NotFoundHttpException) {
            }
        }
        $this->expectException(NotFoundHttpException::class);
        $ewa->jobStatusAction(1);
    }

    public function testAdminMayOpenAnyPurgeJobInTheUserArea()
    {
        $this->my(self::user('jan'))->quarantinePurgeAction(self::post(['mailbox' => 'imap-5', 'mode' => 'all']));
        $admin = $this->my(MailboxAccessTest::user(User::ROLE_ADMIN, [])->setUsername('boss'));
        $this->assertTrue($admin->jobAction(1)['is_admin']);
    }

    public function testClickWhileAnAdminPurgeIsQueuedDoesNotOpenTheAdminsJob()
    {
        $this->purger()->enqueue($this->quarantine->getMailbox('imap-5'), 'all', QuarantinePurge::SOURCE_PANEL);
        $response = $this->my(self::user('jan'))->quarantinePurgeAction(self::post(['mailbox' => 'imap-5', 'mode' => 'all']));

        $this->assertSame('/antispam_my_quarantine', $response->getTargetUrl());
        $this->assertStringContainsString('już w kolejce', $this->session->getFlashBag()->get('info')[0]);
        $this->assertSame(1, $this->jobCount());
    }

    public function testAdminQueuesAPurgeOfAnyMailbox()
    {
        $controller = $this->spambox();
        $response = $controller->quarantinePurgeAction(self::post(['mailbox' => 'imap', 'mode' => 'all', 'shown' => '12']));
        $this->assertSame('/antispam_job_show/1', $response->getTargetUrl());
        $this->assertSame('quarantine.purge:imap:all', $this->db->row(1)['active_key']);

        $response = $controller->quarantinePurgeAction(self::post(['mailbox' => 'imap-77', 'mode' => 'all']));
        $this->assertSame('/antispam_spambox_quarantine', $response->getTargetUrl(), 'unknown mailbox');
        $this->assertSame(1, $this->jobCount());
    }

    public function testGlobalHighRiskPurgeQueuesOneJobPerMailbox()
    {
        $controller = $this->spambox();
        $response = $controller->quarantinePurgeAllAction(self::post([]));

        $this->assertSame('/antispam_job_index/quarantine.purge', $response->getTargetUrl());
        $keys = $this->db->em->getConnection()->fetchFirstColumn('SELECT active_key FROM ' . BackgroundJob::TABLE . ' ORDER BY id');
        $this->assertSame(['quarantine.purge:imap-5:high_risk', 'quarantine.purge:ssh-6:high_risk', 'quarantine.purge:imap:high_risk'], $keys);
        $this->assertStringContainsString('dodano do kolejki 3 zadania', $this->session->getFlashBag()->get('success')[0]);

        $controller->quarantinePurgeAllAction(self::post([]));
        $this->assertSame(3, $this->jobCount(), 'deduped while queued');
        $this->assertStringContainsString('3 już było', $this->session->getFlashBag()->get('success')[0]);
    }
}
