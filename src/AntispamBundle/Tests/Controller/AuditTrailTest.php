<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Command\RulesMakeGlobalCommand;
use AntispamBundle\Controller\AccountController;
use AntispamBundle\Controller\BulkImportController;
use AntispamBundle\Controller\CertController;
use AntispamBundle\Controller\ConfigurationController;
use AntispamBundle\Controller\DnsblController;
use AntispamBundle\Controller\MyController;
use AntispamBundle\Controller\PhishingController;
use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Controller\QuarantineActionController;
use AntispamBundle\Controller\SpamboxController;
use AntispamBundle\Controller\UserController;
use AntispamBundle\Controller\WhitelistController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\PhishingReport;
use AntispamBundle\Entity\User;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Security\AuditSecuritySubscriber;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\DigestTokenService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Tests\Security\MailboxAccessTest;
use AntispamBundle\Tests\Support\InMemoryRepository;
use AntispamBundle\Tests\Support\RecordingAuditLogger;
use AntispamBundle\Tests\Support\RuleFixtures;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Every major area writes an audit entry: rule lists, quarantine (panel, user
 * area, digest link), plugin API, phishing, settings (without secret values),
 * accounts, users, DNSBL, CERT sync, rules:make-global and login / logout.
 */
class AuditTrailTest extends TestCase
{
    private RecordingAuditLogger $audit;

    protected function setUp(): void
    {
        $this->audit = new RecordingAuditLogger();
    }

    /** Controller wired like the real locator, with the recording audit logger. */
    private function wire(AbstractController $controller, ?object $user = null): AbstractController
    {
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(true);
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(fn($name) => '/' . $name);
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
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
            AuditLogger::class => fn() => $this->audit,
        ]));
        return $controller;
    }

    /** New $class with a mock for every constructor argument unless given. */
    private function make(string $class, array $args = []): object
    {
        $params = [];
        foreach ((new \ReflectionClass($class))->getConstructor()->getParameters() as $p) {
            $name = $p->getName();
            if (array_key_exists($name, $args)) {
                $params[] = $args[$name];
            } elseif ($p->getType() instanceof \ReflectionNamedType && !$p->getType()->isBuiltin()) {
                $params[] = $this->createMock($p->getType()->getName());
            } else {
                $params[] = $p->isDefaultValueAvailable() ? $p->getDefaultValue() : '';
            }
        }
        return new $class(...$params);
    }

    private function post(array $data): Request
    {
        return Request::create('/x', 'POST', $data + ['_token' => 't']);
    }

    private static function withId(object $entity, int $id): object
    {
        (new \ReflectionProperty($entity, 'id'))->setValue($entity, $id);
        return $entity;
    }

    private function emWith(array $repos): EntityManagerInterface
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturnCallback(fn($class) => $repos[$class] ?? new InMemoryRepository());
        return $em;
    }

    // ---- rule lists ---------------------------------------------------------

    public function testRuleAddAndDelete()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl');
        $controller = $this->wire(new WhitelistController($db->em, $db->ownership()));

        $controller->addAction($this->post(['host' => 'partner.pl', 'owner' => '*']));
        $this->assertSame(['action' => 'rule.add', 'targetType' => 'whitelist', 'label' => 'partner.pl', 'mailbox' => '*'],
            array_intersect_key($this->audit->last(), array_flip(['action', 'targetType', 'label', 'mailbox'])));

        $db->add(self::withId((new Whitelist())->setEmail('biuro@firma.pl')->setHost('old.pl')->setPatternType('exact'), 9));
        $controller->delAction('9', $this->post([]));
        $last = $this->audit->last();
        $this->assertSame(['rule.delete', '9', 'old.pl', 'biuro@firma.pl'], [$last['action'], $last['targetId'], $last['label'], $last['mailbox']]);
    }

    public function testRejectedRuleIsNotAudited()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl');
        $controller = $this->wire(new WhitelistController($db->em, $db->ownership()));
        $controller->addAction($this->post(['host' => 'x.pl', 'owner' => 'nobody@nowhere.pl']));
        $this->assertSame([], $this->audit->entries);
    }

    public function testBulkImport()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl');
        $controller = $this->wire(new BulkImportController($db->em, $db->ownership()));
        $controller->importAction($this->post(['owner' => '*', 'entries' => "a.pl\nb.pl\na.pl"]), 'blacklist');

        $last = $this->audit->last();
        $this->assertSame(['rule.import', 'blacklist', '*'], [$last['action'], $last['targetType'], $last['mailbox']]);
        $this->assertSame(2, $last['details']['added']);
        $this->assertSame(1, $last['details']['skipped']);
    }

    // ---- quarantine ---------------------------------------------------------

    public function testUserAreaQuarantineActionsAreAudited()
    {
        $quarantine = $this->createMock(QuarantineService::class);
        $quarantine->method('release')->willReturn(['success' => true, 'message' => 'ok', 'sender' => 'a@b.pl']);
        $quarantine->method('delete')->willThrowException(new \RuntimeException('imap down'));
        $jan = MailboxAccessTest::user(User::ROLE_USER, [MailboxAccessTest::account(5, 'jan@firma.pl')]);
        $controller = $this->wire($this->make(MyController::class, ['quarantine' => $quarantine, 'access' => new MailboxAccess()]), $jan);

        $controller->quarantineItemAction($this->post(['mailbox' => 'imap-5', 'id' => '12', 'action' => 'release']));
        $controller->quarantineItemAction($this->post(['mailbox' => 'imap-5', 'id' => '13', 'action' => 'delete']));

        [$release, $delete] = $this->audit->entries;
        $this->assertSame(['quarantine.release', '12', 'a@b.pl'], [$release['action'], $release['targetId'], $release['label']]);
        $this->assertSame(['source' => 'my', 'quarantine' => 'imap-5', 'ok' => true], $release['details']);
        $this->assertSame('quarantine.delete', $delete['action']);
        $this->assertFalse($delete['details']['ok'], 'a failed attempt is recorded as such');
    }

    public function testForeignMailboxIsRefusedBeforeAuditing()
    {
        $jan = MailboxAccessTest::user(User::ROLE_USER, [MailboxAccessTest::account(5, 'jan@firma.pl')]);
        $controller = $this->wire($this->make(MyController::class, ['access' => new MailboxAccess()]), $jan);
        try {
            $controller->quarantineItemAction($this->post(['mailbox' => 'imap-6', 'id' => '1', 'action' => 'delete']));
            $this->fail('expected 403');
        } catch (\Symfony\Component\Security\Core\Exception\AccessDeniedException) {
        }
        $this->assertSame([], $this->audit->entries);
    }

    public function testAdminPanelQuarantineAction()
    {
        $quarantine = $this->createMock(QuarantineService::class);
        $quarantine->method('release')->with('ssh-3', '7', true)->willReturn(['success' => true, 'message' => 'ok', 'sender' => 'x@y.pl']);
        $controller = $this->wire($this->make(SpamboxController::class, ['quarantine' => $quarantine]));

        $controller->quarantineItemAction($this->post(['mailbox' => 'ssh-3', 'id' => '7', 'action' => 'whitelist']));
        $last = $this->audit->last();
        $this->assertSame(['quarantine.whitelist', 'panel'], [$last['action'], $last['details']['source']]);
    }

    public function testDigestLinkActionIsAuditedAsTheLink()
    {
        $tokens = $this->createMock(DigestTokenService::class);
        $tokens->method('usesDefaultSecret')->willReturn(false);
        $tokens->method('verify')->willReturn(['mailbox' => 'imap-5', 'id' => '44', 'action' => 'delete', 'account' => 'jan@firma.pl', 'uidvalidity' => null]);
        $quarantine = $this->createMock(QuarantineService::class);
        $quarantine->method('getMailbox')->willReturn(['key' => 'imap-5', 'account_email' => 'jan@firma.pl']);
        $quarantine->method('delete')->willReturn(['success' => true, 'message' => 'ok', 'sender' => 'spam@x.pl']);
        $controller = $this->getMockBuilder(QuarantineActionController::class)
            ->setConstructorArgs([$tokens, $quarantine])->onlyMethods(['render'])->getMock();
        $controller->method('render')->willReturn(new Response());
        $this->wire($controller);

        $controller->actionAction(Request::create('/q/a.b', 'POST'), 'a.b');
        $last = $this->audit->last();
        $this->assertSame(['quarantine.delete', 'link z raportu', AuditLog::ACTOR_DIGEST_LINK, 'jan@firma.pl', 'digest'],
            [$last['action'], $last['actor'], $last['actorType'], $last['mailbox'], $last['details']['source']]);
    }

    public function testDigestConfirmationPageIsNotAnAction()
    {
        $tokens = $this->createMock(DigestTokenService::class);
        $tokens->method('verify')->willReturn(['mailbox' => 'imap-5', 'id' => '44', 'action' => 'delete', 'account' => null, 'uidvalidity' => null]);
        $controller = $this->getMockBuilder(QuarantineActionController::class)
            ->setConstructorArgs([$tokens, $this->createMock(QuarantineService::class)])->onlyMethods(['render'])->getMock();
        $controller->method('render')->willReturn(new Response());
        $this->wire($controller);

        $controller->actionAction(Request::create('/q/a.b', 'GET'), 'a.b');
        $this->assertSame([], $this->audit->entries);
    }

    // ---- plugin API ---------------------------------------------------------

    public function testPluginReportIsAuditedWithThePluginAccount()
    {
        $account = $this->createMock(Account::class);
        $account->method('getId')->willReturn(7);
        $account->method('getEmail')->willReturn('jan@firma.pl');
        $plugin = $this->createMock(PluginService::class);
        $plugin->method('isEnabled')->willReturn(true);
        $plugin->method('hit')->willReturn(true);
        $plugin->method('accountForToken')->willReturn($account);
        $plugin->method('learn')->willReturn(['sender' => 'spam@x.pl', 'rules' => []]);
        $controller = $this->wire($this->make(PluginApiController::class, ['plugin' => $plugin]));

        $request = Request::create('/api/plugin/report', 'POST', [], [], [], [], json_encode(['raw_base64' => base64_encode("From: a@b\r\n\r\nx"), 'verdict' => 'ham']));
        $request->headers->set('Authorization', 'Bearer good');
        $controller->reportAction($request);

        $last = $this->audit->last();
        $this->assertSame(['plugin.report', 'jan@firma.pl', AuditLog::ACTOR_PLUGIN, 'jan@firma.pl', 'ham'],
            [$last['action'], $last['actor'], $last['actorType'], $last['mailbox'], $last['details']['verdict']]);
    }

    public function testPluginLoginFailureNeverStoresThePassword()
    {
        $plugin = $this->createMock(PluginService::class);
        $plugin->method('isEnabled')->willReturn(true);
        $plugin->method('hit')->willReturn(true);
        $plugin->method('authenticate')->willReturn(null);
        $controller = $this->wire($this->make(PluginApiController::class, ['plugin' => $plugin]));

        $controller->loginAction(Request::create('/api/plugin/login', 'POST', [], [], [], [], json_encode(['email' => 'jan@firma.pl', 'password' => 'Sekret123'])));
        $last = $this->audit->last();
        $this->assertSame(['plugin.login_failed', 'jan@firma.pl'], [$last['action'], $last['mailbox']]);
        $this->assertStringNotContainsString('Sekret123', json_encode($this->audit->entries));
    }

    // ---- phishing -----------------------------------------------------------

    public function testPhishingDeleteAndEmlDownload()
    {
        $report = self::withId((new PhishingReport())->setAccountEmail('jan@firma.pl')->setSender('ceo@fake.pl'), 3);
        $em = $this->emWith([PhishingReport::class => new InMemoryRepository([$report])]);
        $controller = $this->wire($this->make(PhishingController::class, ['em' => $em]));

        $controller->emlAction(3);
        $controller->deleteAction(3, $this->post([]));
        $this->assertSame(['phishing.eml_download', 'phishing.delete'], $this->audit->actions());
        $this->assertSame([3, 'ceo@fake.pl', 'jan@firma.pl'], [$this->audit->last()['targetId'], $this->audit->last()['label'], $this->audit->last()['mailbox']]);
    }

    public function testPhishingStatusChange()
    {
        $report = self::withId((new PhishingReport())->setAccountEmail('jan@firma.pl')->setSender('ceo@fake.pl'), 3);
        $em = $this->emWith([PhishingReport::class => new InMemoryRepository([$report])]);
        $controller = $this->wire($this->make(PhishingController::class, ['em' => $em]));
        $before = $report->getStatus();

        $controller->updateAction(3, $this->post(['status' => 'confirmed', 'note' => 'x']));
        $this->assertSame(['status_from' => $before, 'status_to' => 'confirmed'], $this->audit->last()['details']);
    }

    // ---- settings -----------------------------------------------------------

    public function testSettingsSaveRecordsFieldNamesNotSecrets()
    {
        $controller = $this->wire($this->make(ConfigurationController::class));
        $controller->spamConfigAction($this->post(['config' => ['scoring_enabled' => '1', 'vt_api_key' => 'VT-SECRET-123', 'spam_threshold' => '9']]));

        $last = $this->audit->last();
        $this->assertSame(['settings.save', 'spam'], [$last['action'], $last['targetId']]);
        $this->assertContains('spam_threshold', $last['details']['fields']);
        $this->assertSame(['vt_api_key'], $last['details']['secrets_changed']);
        $this->assertStringNotContainsString('VT-SECRET-123', json_encode($this->audit->entries));
    }

    public function testFeedSettingsNeverLogKeys()
    {
        $controller = $this->wire($this->make(ConfigurationController::class));
        $controller->feedConfigAction($this->post(['config' => ['enabled' => '1', 'server_key' => 'SRV-KEY-XYZ', 'remote_key' => 'REM-KEY-XYZ']]));
        $this->assertSame('feed', $this->audit->last()['targetId']);
        $this->assertStringNotContainsString('KEY-XYZ', json_encode($this->audit->entries));
    }

    // ---- accounts / users / DNSBL / CERT -------------------------------------

    public function testAccountDeleteAndHostKeyReset()
    {
        $account = self::withId((new Account())->setName('Biuro')->setEmail('biuro@firma.pl')->setConnectionType(Account::CONNECTION_SSH), 4);
        $em = $this->emWith([Account::class => new InMemoryRepository([$account])]);
        $controller = $this->wire($this->make(AccountController::class, ['em' => $em]));

        $controller->resetHostKeyAction('4', $this->post([]));
        $controller->delAction('4', $this->post([]));
        $this->assertSame(['account.host_key_reset', 'account.delete'], $this->audit->actions());
        $this->assertSame(['4', 'Biuro', 'biuro@firma.pl'], [$this->audit->last()['targetId'], $this->audit->last()['label'], $this->audit->last()['mailbox']]);
    }

    public function testAccountEditLogsMailboxSettingsOverrides()
    {
        $account = self::withId((new Account())->setName('Biuro')->setEmail('biuro@firma.pl')->setConnectionType(Account::CONNECTION_IMAP)->setDigestHour(7), 5);
        $em = $this->emWith([Account::class => new InMemoryRepository([$account])]);
        $scoring = new \AntispamBundle\Services\ScoringService($em);
        $resolver = new \AntispamBundle\Services\MailboxSettingsResolver($scoring, $this->createMock(\AntispamBundle\Services\ConfigService::class), $em);
        $controller = $this->wire($this->make(AccountController::class, ['em' => $em, 'mailboxSettings' => $resolver]));
        $form = ['name' => 'Biuro', 'email' => 'biuro@firma.pl', 'connection_type' => 'imap', 'imap_host' => 'imap.firma.pl', 'imap_port' => '993', 'imap_login' => 'biuro'];

        // quarantine >= spam (inherited 10) is refused, nothing changes.
        $controller->editAction('5', $this->post(['account' => $form + ['quarantine_threshold' => '10']]));
        $this->assertSame([], $this->audit->actions());
        $this->assertNull($account->getQuarantineThreshold());

        $controller->editAction('5', $this->post(['account' => $form + ['spam_threshold' => '6', 'digest_recipient' => 'szef@firma.pl', 'digest_hour' => '']]));
        $details = $this->audit->last()['details'];
        $this->assertSame('account.edit', $this->audit->last()['action']);
        $this->assertSame(['spam_threshold' => 6, 'digest_recipient' => 'szef@firma.pl'], $details['settings_overrides']);
        $this->assertSame(['spam_threshold', 'digest_recipient', 'digest_hour'], $details['settings_changed']);
        $this->assertSame(6, $account->getSpamThreshold());
        $this->assertNull($account->getDigestHour());
    }

    public function testUserDelete()
    {
        $ola = self::withId((new User())->setUsername('ola')->setRole(User::ROLE_USER), 8);
        $em = $this->emWith([User::class => new InMemoryRepository([$ola])]);
        $admin = new InMemoryUser('admin', 'x', ['ROLE_ADMIN']);
        $controller = $this->wire($this->make(UserController::class, ['em' => $em, 'envAdminUser' => 'admin']), $admin);

        $controller->deleteAction(8, $this->post([]));
        $this->assertSame(['user.delete', 8, 'ola'], [$this->audit->last()['action'], $this->audit->last()['targetId'], $this->audit->last()['label']]);
    }

    public function testDnsblToggleAndDelete()
    {
        $p = self::withId((new DnsblProvider())->setName('ZEN')->setZone('zen.example')->setScore(5)->setEnabled(true), 2);
        $em = $this->emWith([DnsblProvider::class => new InMemoryRepository([$p])]);
        $controller = $this->wire($this->make(DnsblController::class, ['em' => $em]));

        $controller->toggleAction('2', $this->post([]));
        $this->assertSame(['dnsbl.toggle', 'zen.example', ['enabled' => false]], [$this->audit->last()['action'], $this->audit->last()['label'], $this->audit->last()['details']]);
        $controller->delAction('2', $this->post([]));
        $this->assertSame('dnsbl.delete', $this->audit->last()['action']);
    }

    public function testManualCertSync()
    {
        $cert = $this->createMock(CertHoleService::class);
        $cert->method('sync')->willReturn(['ok' => true, 'message' => 'Pobrano 1000 domen']);
        $controller = $this->wire($this->make(CertController::class, ['cert' => $cert]));

        $controller->syncAction($this->post([]));
        $this->assertSame(['cert.sync', 'Pobrano 1000 domen', ['ok' => true]], [$this->audit->last()['action'], $this->audit->last()['label'], $this->audit->last()['details']]);
    }

    public function testRulesMakeGlobalCommand()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl');
        $db->add((new Whitelist())->setEmail('biuro@firma.pl')->setHost('a.pl')->setPatternType('exact'));
        $tester = new CommandTester(new RulesMakeGlobalCommand($db->em, $db->ownership(), $this->audit));

        $tester->execute(['--dry-run' => true]);
        $this->assertSame([], $this->audit->entries, 'a dry run changes nothing');
        $tester->execute([]);
        $this->assertSame(['rules.make_global', 'biuro@firma.pl', 1], [$this->audit->last()['action'], $this->audit->last()['mailbox'], $this->audit->last()['details']['moved']]);
    }

    // ---- login / logout -----------------------------------------------------

    public function testLoginSuccessFailureAndLogout()
    {
        $subscriber = new AuditSecuritySubscriber($this->audit);
        $request = Request::create('/login', 'POST', ['_username' => 'jan', '_password' => 'Sekret123']);
        $jan = (new User())->setUsername('jan')->setRole(User::ROLE_USER);
        $authenticator = $this->createMock(AuthenticatorInterface::class);
        $token = new UsernamePasswordToken($jan, 'main', $jan->getRoles());

        $subscriber->onLoginSuccess(new LoginSuccessEvent($authenticator, new SelfValidatingPassport(new UserBadge('jan', fn() => $jan)), $token, $request, null, 'main'));
        $subscriber->onLoginFailure(new LoginFailureEvent(new BadCredentialsException(), $authenticator, $request, null, 'main',
            new Passport(new UserBadge('jan'), new PasswordCredentials('Sekret123'))));
        $subscriber->onLogout(new LogoutEvent($request, $token));

        [$ok, $failed, $logout] = $this->audit->entries;
        $this->assertSame(['auth.login', 'jan', AuditLog::ACTOR_USER, User::ROLE_USER], [$ok['action'], $ok['actor'], $ok['actorType'], $ok['role']]);
        $this->assertSame(['auth.login_failed', 'jan', AuditLog::ACTOR_ANONYMOUS, 'BadCredentialsException'], [$failed['action'], $failed['actor'], $failed['actorType'], $failed['details']['reason']]);
        $this->assertSame(['auth.logout', 'jan'], [$logout['action'], $logout['actor']]);
        $this->assertStringNotContainsString('Sekret123', json_encode($this->audit->entries));
    }

    public function testEnvAdminLogin()
    {
        $subscriber = new AuditSecuritySubscriber($this->audit);
        $admin = new InMemoryUser('admin', 'x', ['ROLE_ADMIN']);
        $subscriber->onLoginSuccess(new LoginSuccessEvent($this->createMock(AuthenticatorInterface::class),
            new SelfValidatingPassport(new UserBadge('admin', fn() => $admin)), new UsernamePasswordToken($admin, 'main', ['ROLE_ADMIN']), new Request(), null, 'main'));
        $this->assertSame(['admin', AuditLog::ACTOR_ENV_ADMIN, 'ROLE_ADMIN'], [$this->audit->last()['actor'], $this->audit->last()['actorType'], $this->audit->last()['role']]);
    }
}
