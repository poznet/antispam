<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\MyController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\SpamFolderService;
use AntispamBundle\Tests\Security\MailboxAccessTest;
use AntispamBundle\Tests\Support\RecordingAuditLogger;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * /my/spam: listing and release from the SPAM folder of own mailboxes only.
 */
class MySpamControllerTest extends TestCase
{
    /** @var QuarantineService&MockObject */
    private $quarantine;
    /** @var SpamFolderService&MockObject */
    private $spam;
    /** @var DeferredAgentSync&MockObject */
    private $sync;
    private RecordingAuditLogger $audit;
    private Session $session;
    private bool $csrfValid = true;

    private const MAILBOXES = [
        ['key' => 'imap-5', 'label' => 'Jan', 'account_email' => 'jan@firma.pl', 'recipient' => 'jan@firma.pl'],
        ['key' => 'imap-6', 'label' => 'Ola', 'account_email' => 'ola@firma.pl', 'recipient' => 'ola@firma.pl'],
        ['key' => 'ssh-7', 'label' => 'Jan SSH', 'account_email' => 'jan@ssh.pl', 'recipient' => 'jan@ssh.pl'],
        ['key' => 'imap', 'label' => 'Legacy', 'account_email' => 'stara@firma.pl', 'recipient' => 'stara@firma.pl'],
    ];

    private function controller(object $user): MyController
    {
        $this->quarantine = $this->createMock(QuarantineService::class);
        $this->quarantine->method('getMailboxes')->willReturn(self::MAILBOXES);
        $this->quarantine->method('getMailbox')->willReturnCallback(function ($key) {
            foreach (self::MAILBOXES as $m) {
                if ($m['key'] === $key) {
                    return $m;
                }
            }
            return null;
        });
        $this->spam = $this->createMock(SpamFolderService::class);
        $this->sync = $this->createMock(DeferredAgentSync::class);
        $this->audit = new RecordingAuditLogger();
        $this->session = new Session(new MockArraySessionStorage());

        $controller = new MyController($this->createMock(EntityManagerInterface::class), $this->quarantine, new MailboxAccess(),
            $this->createMock(UserPasswordHasherInterface::class), $this->spam, $this->sync);
        $tokens = new TokenStorage();
        $tokens->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturnCallback(fn() => $this->csrfValid);
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(fn($name) => '/' . $name);
        $stack = new RequestStack();
        $request = new Request();
        $request->setSession($this->session);
        $stack->push($request);
        $controller->setContainer(new ServiceLocator([
            'security.token_storage' => fn() => $tokens,
            'security.csrf.token_manager' => fn() => $csrf,
            'router' => fn() => $router,
            'request_stack' => fn() => $stack,
            AuditLogger::class => fn() => $this->audit,
        ]));
        return $controller;
    }

    private function jan(): User
    {
        return MailboxAccessTest::user(User::ROLE_USER, [
            MailboxAccessTest::account(5, 'jan@firma.pl'),
            MailboxAccessTest::account(7, 'jan@ssh.pl', Account::CONNECTION_SSH),
        ]);
    }

    private function post(array $data): Request
    {
        return Request::create('/my/spam/action', 'POST', $data + ['_token' => 't']);
    }

    private static function item(string $id, array $reasons): array
    {
        return ['id' => $id, 'from' => 'a@b.pl', 'from_name' => '', 'subject' => 's', 'date' => null, 'score' => 12, 'reasons' => $reasons, 'uidvalidity' => 42];
    }

    public function testListingCoversOwnMailboxesOnly()
    {
        $controller = $this->controller($this->jan());
        $this->spam->expects($this->exactly(2))->method('listItems')
            ->with($this->callback(fn($key) => in_array($key, ['imap-5', 'ssh-7'], true)))
            ->willReturnCallback(fn($key) => $key === 'ssh-7' ? throw new \RuntimeException('/home/u: agent error') : ['items' => [self::item('3', [['rule' => 'blacklist:b.pl', 'score' => 12]])], 'total' => 1]);

        $vars = $controller->spamAction();
        $this->assertSame(['imap-5', 'ssh-7'], array_column($vars['mailboxes'], 'key'));
        $this->assertFalse($vars['mailboxes'][0]['items'][0]['high_risk']);
        $this->assertNotNull($vars['mailboxes'][1]['error']);
        $this->assertStringNotContainsString('/home/u', $vars['mailboxes'][1]['error']);
    }

    public static function foreignKeys(): iterable
    {
        foreach (['imap-6', 'ssh-5', 'imap-7', 'ssh-99', 'imap', '', 'imap-5 '] as $key) {
            foreach (['release', 'whitelist'] as $action) {
                yield "$key/$action" => [$key, $action];
            }
        }
    }

    #[DataProvider('foreignKeys')]
    public function testForeignMailboxIsForbidden(string $key, string $action)
    {
        $controller = $this->controller($this->jan());
        $this->spam->expects($this->never())->method('release');
        $this->spam->expects($this->never())->method('listItems');

        $this->expectException(AccessDeniedException::class);
        $controller->spamItemAction($this->post(['mailbox' => $key, 'id' => '3', 'action' => $action]));
    }

    public function testOwnReleaseIsDelegatedWithUidValidityAndAudited()
    {
        $controller = $this->controller($this->jan());
        $this->spam->expects($this->once())->method('release')->with('imap-5', '3', false, 42)
            ->willReturn(['success' => true, 'message' => 'ok', 'sender' => 'a@b.pl']);
        $this->sync->expects($this->never())->method('deferForOwner');

        $response = $controller->spamItemAction($this->post(['mailbox' => 'imap-5', 'id' => '3', 'action' => 'release', 'uidvalidity' => '42']));
        $this->assertSame('/antispam_my_spam', $response->getTargetUrl());
        $entry = $this->audit->last();
        $this->assertSame(['spam.release', '3', 'a@b.pl', 'jan@firma.pl'], [$entry['action'], $entry['targetId'], $entry['label'], $entry['mailbox']]);
        $this->assertSame(['source' => 'my', 'mailbox_id' => 'imap-5', 'ok' => true], $entry['details']);
    }

    public function testWhitelistOfLowRiskSshMessageSchedulesAnAgentSync()
    {
        $controller = $this->controller($this->jan());
        $this->spam->method('listItems')->willReturn(['items' => [self::item('1.M1.h', [['rule' => 'dnsbl:zen', 'score' => 12]])], 'total' => 1]);
        $this->spam->expects($this->once())->method('release')->with('ssh-7', '1.M1.h', true, null)
            ->willReturn(['success' => true, 'message' => 'ok', 'sender' => 'a@b.pl', 'whitelisted' => true]);
        $this->sync->expects($this->once())->method('deferForOwner')->with('jan@ssh.pl');

        $controller->spamItemAction($this->post(['mailbox' => 'ssh-7', 'id' => '1.M1.h', 'action' => 'whitelist']));
        $this->assertSame('spam.whitelist', $this->audit->last()['action']);
    }

    public static function riskyListings(): array
    {
        return [
            'high risk' => [[self::item('3', [['rule' => 'clamav:Eicar', 'score' => 100]])]],
            'unknown score' => [[self::item('3', QuarantineService::unknownScoreReasons())]],
            'not listed' => [[self::item('4', [['rule' => 'dnsbl:zen', 'score' => 12]])]],
        ];
    }

    #[DataProvider('riskyListings')]
    public function testWhitelistIsRefusedFailClosed(array $items)
    {
        $controller = $this->controller($this->jan());
        $this->spam->method('listItems')->willReturn(['items' => $items, 'total' => count($items)]);
        $this->spam->expects($this->never())->method('release');

        $controller->spamItemAction($this->post(['mailbox' => 'imap-5', 'id' => '3', 'action' => 'whitelist']));
        $this->assertFalse($this->audit->last()['details']['ok']);
    }

    public function testCsrfIsRequired()
    {
        $controller = $this->controller($this->jan());
        $this->csrfValid = false;
        $this->spam->expects($this->never())->method('release');
        $controller->spamItemAction($this->post(['mailbox' => 'imap-5', 'id' => '3', 'action' => 'release']));
        $this->assertSame([], $this->audit->entries);
    }

    public function testUnknownActionDoesNothing()
    {
        $controller = $this->controller($this->jan());
        $this->spam->expects($this->never())->method('release');
        $controller->spamItemAction($this->post(['mailbox' => 'imap-5', 'id' => '3', 'action' => 'delete']));
    }

    public function testAdminMayActOnAnyMailbox()
    {
        $controller = $this->controller(new InMemoryUser('admin', 'h', ['ROLE_ADMIN']));
        $this->spam->expects($this->once())->method('release')->with('imap', '3')->willReturn(['success' => true, 'message' => 'ok', 'sender' => '']);
        $controller->spamItemAction($this->post(['mailbox' => 'imap', 'id' => '3', 'action' => 'release']));
    }
}
