<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\MyRulesController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\User;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Tests\Security\MailboxAccessTest;
use AntispamBundle\Tests\Support\RecordingAuditLogger;
use AntispamBundle\Tests\Support\RuleFixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * /my/rules: a user manages exact / wildcard sender rules of THEIR mailboxes
 * only. Foreign owners, '*' and foreign / global rule ids are refused
 * server-side; regex is refused; SSH mailboxes get an agent sync scheduled.
 */
class MyRulesControllerTest extends TestCase
{
    private RuleFixtures $db;
    private RecordingAuditLogger $audit;
    /** @var DeferredAgentSync&MockObject */
    private $sync;
    private Session $session;
    private bool $csrfValid = true;
    /** @var object[] */
    private array $removed = [];

    protected function setUp(): void
    {
        $this->db = new RuleFixtures($this, null);
        $this->db->repos[Account::class]->add(MailboxAccessTest::account(5, 'jan@firma.pl'));
        $this->db->repos[Account::class]->add(MailboxAccessTest::account(6, 'ola@firma.pl'));
        $this->db->repos[Account::class]->add(MailboxAccessTest::account(7, 'jan@ssh.pl', Account::CONNECTION_SSH));
        $this->db->em->method('remove')->willReturnCallback(function ($e) {
            $this->removed[] = $e;
        });
        $this->audit = new RecordingAuditLogger();
        $this->sync = $this->createMock(DeferredAgentSync::class);
        $this->session = new Session(new MockArraySessionStorage());
    }

    private function jan(): User
    {
        return MailboxAccessTest::user(User::ROLE_USER, [
            MailboxAccessTest::account(5, 'jan@firma.pl'),
            MailboxAccessTest::account(7, 'jan@ssh.pl', Account::CONNECTION_SSH),
        ]);
    }

    private function controller(object $user): MyRulesController
    {
        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('getSpamThreshold')->willReturn(12);
        $controller = new MyRulesController($this->db->em, new MailboxAccess(), $this->db->ownership(), $this->sync, $scoring);

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

    private function post(array $data): Request
    {
        return Request::create('/my/rules/x', 'POST', $data + ['_token' => 't']);
    }

    private function rule(string $class, int $id, string $owner, string $value): object
    {
        $rule = new $class();
        $rule->setEmail($owner)->setPatternType('exact');
        match ($class) {
            Whitelist::class, Blacklist::class => $rule->setHost($value),
            EmailWhitelist::class => $rule->setWhitelistemail($value),
            EmailBlacklist::class => $rule->setBlacklistemail($value),
        };
        (new \ReflectionProperty($class, 'id'))->setValue($rule, $id);
        $this->db->repos[$class]->add($rule);
        return $rule;
    }

    private function flashes(string $type): string
    {
        return implode(' ', $this->session->getFlashBag()->peekAll()[$type] ?? []);
    }

    // ---- add ---------------------------------------------------------------

    public function testUserAddsAWhitelistRuleForOwnMailbox()
    {
        $this->sync->expects($this->once())->method('deferForOwner')->with('jan@firma.pl')->willReturn(0);
        $this->controller($this->jan())->addAction($this->post([
            'list' => 'email_whitelist', 'owner' => 'JAN@firma.pl', 'value' => 'Szef@Firma.pl', 'pattern_type' => 'exact',
        ]));

        $this->assertCount(1, $this->db->persisted);
        $rule = $this->db->persisted[0];
        $this->assertInstanceOf(EmailWhitelist::class, $rule);
        $this->assertSame('jan@firma.pl', $rule->getEmail(), 'canonical owner of the account');
        $this->assertSame('szef@firma.pl', $rule->getWhitelistemail());
        $entry = $this->audit->last();
        $this->assertSame(['rule.add', 'email_whitelist', 'szef@firma.pl', 'jan@firma.pl'], [$entry['action'], $entry['targetType'], $entry['label'], $entry['mailbox']]);
        $this->assertSame('my', $entry['details']['source']);
    }

    public function testBlacklistRuleGetsADecisiveScore()
    {
        $this->controller($this->jan())->addAction($this->post([
            'list' => 'blacklist', 'owner' => 'jan@firma.pl', 'value' => '*.spam.example', 'pattern_type' => 'wildcard',
        ]));
        $this->assertSame(12, $this->db->persisted[0]->getScore());
        $this->assertSame('wildcard', $this->db->persisted[0]->getPatternType());
        $this->assertStringContainsString('nie jest przenoszona', $this->flashes('success'), 'no retroactive pass, and the user is told');
    }

    public static function foreignOwners(): array
    {
        return [['ola@firma.pl'], ['*'], [''], ['jan@firma.pl.evil'], ['nikt@nigdzie.pl']];
    }

    #[DataProvider('foreignOwners')]
    public function testForeignOrGlobalOwnerIsForbidden(string $owner)
    {
        $this->sync->expects($this->never())->method('deferForOwner');
        try {
            $this->controller($this->jan())->addAction($this->post(['list' => 'email_blacklist', 'owner' => $owner, 'value' => 'a@b.pl']));
            $this->fail('expected 403');
        } catch (AccessDeniedException) {
        }
        $this->assertSame([], $this->db->persisted);
        $this->assertSame([], $this->audit->entries);
    }

    public function testRegexIsRefusedForUsers()
    {
        $this->controller($this->jan())->addAction($this->post([
            'list' => 'email_whitelist', 'owner' => 'jan@firma.pl', 'value' => '.*@firma\.pl', 'pattern_type' => 'regex',
        ]));
        $this->assertSame([], $this->db->persisted);
        $this->assertStringContainsString('tylko administrator', $this->flashes('danger'));
    }

    public function testCatchAllWhitelistIsRefused()
    {
        $this->controller($this->jan())->addAction($this->post([
            'list' => 'email_whitelist', 'owner' => 'jan@firma.pl', 'value' => '*@*', 'pattern_type' => 'wildcard',
        ]));
        $this->assertSame([], $this->db->persisted);
    }

    public function testDuplicateOfOwnOrGlobalRuleIsNotAddedAgain()
    {
        $this->rule(EmailWhitelist::class, 1, '*', 'szef@firma.pl');
        $this->rule(Whitelist::class, 2, 'jan@firma.pl', 'firma.pl');
        $controller = $this->controller($this->jan());

        $controller->addAction($this->post(['list' => 'email_whitelist', 'owner' => 'jan@firma.pl', 'value' => 'szef@firma.pl']));
        $controller->addAction($this->post(['list' => 'whitelist', 'owner' => 'jan@firma.pl', 'value' => '@firma.pl']));
        $this->assertSame([], $this->db->persisted);
        $this->assertStringContainsString('już istnieje', $this->flashes('info'));
    }

    public function testCsrfIsRequired()
    {
        $this->csrfValid = false;
        $this->expectException(AccessDeniedException::class);
        $this->controller($this->jan())->addAction($this->post(['list' => 'email_whitelist', 'owner' => 'jan@firma.pl', 'value' => 'a@b.pl']));
    }

    public function testSshMailboxGetsAnAgentSyncScheduled()
    {
        $this->sync->expects($this->once())->method('deferForOwner')->with('jan@ssh.pl')->willReturn(1);
        $this->controller($this->jan())->addAction($this->post(['list' => 'email_blacklist', 'owner' => 'jan@ssh.pl', 'value' => 'a@spam.pl']));
        $this->assertStringContainsString('agenta', $this->flashes('info'));
    }

    // ---- delete ------------------------------------------------------------

    public function testUserDeletesOwnRule()
    {
        $rule = $this->rule(EmailBlacklist::class, 3, 'jan@ssh.pl', 'a@spam.pl');
        $this->sync->expects($this->once())->method('deferForOwner')->with('jan@ssh.pl')->willReturn(1);
        $this->controller($this->jan())->deleteAction($this->post(['list' => 'email_blacklist', 'id' => '3']));

        $this->assertSame([$rule], $this->removed);
        $entry = $this->audit->last();
        $this->assertSame(['rule.delete', 3, 'a@spam.pl', 'jan@ssh.pl', 'my'], [$entry['action'], $entry['targetId'], $entry['label'], $entry['mailbox'], $entry['details']['source']]);
    }

    public static function forbiddenRules(): array
    {
        return [
            'other mailbox' => [EmailWhitelist::class, 'email_whitelist', 'ola@firma.pl'],
            'global rule' => [Blacklist::class, 'blacklist', '*'],
            'legacy mailbox' => [Whitelist::class, 'whitelist', 'stara@firma.pl'],
        ];
    }

    #[DataProvider('forbiddenRules')]
    public function testForeignAndGlobalRulesCannotBeDeletedById(string $class, string $list, string $owner)
    {
        $this->rule($class, 9, $owner, $class === EmailWhitelist::class ? 'x@y.pl' : 'y.pl');
        $this->sync->expects($this->never())->method('deferForOwner');
        try {
            $this->controller($this->jan())->deleteAction($this->post(['list' => $list, 'id' => '9']));
            $this->fail('expected 403');
        } catch (AccessDeniedException) {
        }
        $this->assertSame([], $this->removed);
        $this->assertSame([], $this->audit->entries);
    }

    public function testIdIsOnlyLookedUpInTheGivenList()
    {
        // id 3 exists in email_blacklist (foreign); asking the whitelist for it finds nothing.
        $this->rule(EmailBlacklist::class, 3, 'ola@firma.pl', 'a@spam.pl');
        $this->controller($this->jan())->deleteAction($this->post(['list' => 'email_whitelist', 'id' => '3']));
        $this->assertSame([], $this->removed);
    }

    // ---- admin + listing ------------------------------------------------------

    public function testAdminMayManageAnyAccountButNotGlobalRules()
    {
        $admin = new InMemoryUser('admin', 'h', ['ROLE_ADMIN']);
        $this->controller($admin)->addAction($this->post(['list' => 'email_whitelist', 'owner' => 'ola@firma.pl', 'value' => 'a@b.pl']));
        $this->assertSame('ola@firma.pl', $this->db->persisted[0]->getEmail());

        $this->rule(Blacklist::class, 4, '*', 'spam.pl');
        $this->expectException(AccessDeniedException::class);
        $this->controller($admin)->deleteAction($this->post(['list' => 'blacklist', 'id' => '4']));
    }

    public function testListingShowsOnlyOwnRules()
    {
        $this->rule(EmailWhitelist::class, 1, 'jan@firma.pl', 'mine@x.pl');
        $this->rule(EmailWhitelist::class, 2, 'ola@firma.pl', 'hers@x.pl');
        $this->rule(EmailWhitelist::class, 3, '*', 'global@x.pl');

        $twig = $this->createMock(\Twig\Environment::class);
        $vars = null;
        $twig->method('render')->willReturnCallback(function ($t, $v) use (&$vars) {
            $vars = $v;
            return '';
        });
        $controller = $this->controller($this->jan());
        $locator = (new \ReflectionProperty($controller, 'container'))->getValue($controller);
        $controller->setContainer(new ServiceLocator([
            'twig' => fn() => $twig,
            'security.token_storage' => fn() => $locator->get('security.token_storage'),
        ]));
        $controller->indexAction();

        $values = array_map(fn($r) => $r->getWhitelistemail(), $vars['lists']['email_whitelist']['rules']);
        $this->assertSame(['mine@x.pl'], $values);
        $this->assertSame(['jan@firma.pl', 'jan@ssh.pl'], $vars['owners']);
        $this->assertSame(['jan@ssh.pl'], $vars['ssh_owners']);
    }
}
