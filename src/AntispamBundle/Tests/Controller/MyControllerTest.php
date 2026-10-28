<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\MyController;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Tests\Security\MailboxAccessTest;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Flash\FlashBag;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * IDOR checks of the release / whitelist / delete endpoint: the mailbox key
 * and message id come from the request, so a user must not be able to act on
 * a mailbox that is not assigned to them.
 */
class MyControllerTest extends TestCase
{
    /** @var QuarantineService&MockObject */
    private $quarantine;

    private function controller(User $user): MyController
    {
        $this->quarantine = $this->createMock(QuarantineService::class);
        $controller = new MyController(
            $this->createMock(EntityManagerInterface::class),
            $this->quarantine,
            new MailboxAccess(),
            $this->createMock(UserPasswordHasherInterface::class),
        );

        $tokens = new TokenStorage();
        $tokens->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(true);
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(fn($name) => '/' . $name);
        $stack = new RequestStack();
        $session = new Session(new MockArraySessionStorage());
        $request = new Request();
        $request->setSession($session);
        $stack->push($request);

        $controller->setContainer(new ServiceLocator([
            'security.token_storage' => fn() => $tokens,
            'security.csrf.token_manager' => fn() => $csrf,
            'router' => fn() => $router,
            'request_stack' => fn() => $stack,
            'security.authorization_checker' => fn() => throw new \LogicException('not used'),
        ]));

        return $controller;
    }

    private function post(array $data): Request
    {
        return Request::create('/my/quarantine/action', 'POST', $data + ['_token' => 't']);
    }

    private function jan(): User
    {
        return MailboxAccessTest::user(User::ROLE_USER, [MailboxAccessTest::account(5, 'jan@firma.pl')]);
    }

    #[DataProvider('foreignKeys')]
    public function testForeignMailboxIsForbiddenForEveryAction(string $key, string $action)
    {
        $controller = $this->controller($this->jan());
        $this->quarantine->expects($this->never())->method('release');
        $this->quarantine->expects($this->never())->method('delete');
        $this->quarantine->expects($this->never())->method('listItems');

        $this->expectException(AccessDeniedException::class);
        $controller->quarantineItemAction($this->post(['mailbox' => $key, 'id' => '1', 'action' => $action]));
    }

    public static function foreignKeys(): iterable
    {
        foreach (['imap-6', 'ssh-5', 'ssh-99', 'imap', ''] as $key) {
            foreach (['release', 'whitelist', 'delete'] as $action) {
                yield "$key/$action" => [$key, $action];
            }
        }
    }

    public function testOwnMailboxReleaseIsDelegated()
    {
        $controller = $this->controller($this->jan());
        $this->quarantine->expects($this->once())->method('release')->with('imap-5', '12')
            ->willReturn(['success' => true, 'message' => 'ok', 'sender' => '']);

        $response = $controller->quarantineItemAction($this->post(['mailbox' => 'imap-5', 'id' => '12', 'action' => 'release']));
        $this->assertSame('/antispam_my_quarantine', $response->getTargetUrl());
    }

    public function testOwnMailboxDelete()
    {
        $controller = $this->controller($this->jan());
        $this->quarantine->expects($this->once())->method('delete')->with('imap-5', '12')
            ->willReturn(['success' => true, 'message' => 'ok', 'sender' => '']);

        $controller->quarantineItemAction($this->post(['mailbox' => 'imap-5', 'id' => '12', 'action' => 'delete']));
    }

    public function testWhitelistOfUnlistedMessageIsRefused()
    {
        $controller = $this->controller($this->jan());
        $this->quarantine->method('listItems')->willReturn([]);
        $this->quarantine->expects($this->never())->method('release');

        $controller->quarantineItemAction($this->post(['mailbox' => 'imap-5', 'id' => '12', 'action' => 'whitelist']));
    }

    public function testWhitelistOfHighRiskMessageIsRefused()
    {
        $controller = $this->controller($this->jan());
        $this->quarantine->method('listItems')->willReturn([
            ['id' => '12', 'from' => 'a@b.pl', 'from_name' => '', 'subject' => 's', 'date' => null, 'score' => 9, 'reasons' => [['rule' => 'impersonation_display_name', 'score' => 9]]],
        ]);
        $this->quarantine->expects($this->never())->method('release');

        $controller->quarantineItemAction($this->post(['mailbox' => 'imap-5', 'id' => '12', 'action' => 'whitelist']));
    }

    public function testAdminMayActOnAnyMailbox()
    {
        $controller = $this->controller(MailboxAccessTest::user(User::ROLE_ADMIN, []));
        $this->quarantine->expects($this->once())->method('release')->with('ssh-77', 'x')
            ->willReturn(['success' => true, 'message' => 'ok', 'sender' => '']);

        $controller->quarantineItemAction($this->post(['mailbox' => 'ssh-77', 'id' => 'x', 'action' => 'release']));
    }
}
