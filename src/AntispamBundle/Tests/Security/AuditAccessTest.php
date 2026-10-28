<?php

namespace AntispamBundle\Tests\Security;

use AntispamBundle\Controller\AuditController;
use AntispamBundle\Controller\MyController;
use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Controller\WhitelistController;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\AuditSecuritySubscriber;
use AntispamBundle\Services\AuditLogger;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * The audit log is for administrators only, and the real container wires the
 * logger into the controllers and the login / logout events. No database.
 */
class AuditAccessTest extends WebTestCase
{
    public static function auditPaths(): array
    {
        return [['/audit'], ['/audit/export.csv']];
    }

    #[DataProvider('auditPaths')]
    public function testAccessControlRequiresAdmin(string $path)
    {
        self::bootKernel();
        [$attributes] = self::getContainer()->get('security.access_map')->getPatterns(Request::create($path));
        $this->assertSame(['ROLE_ADMIN'], $attributes);
    }

    #[DataProvider('auditPaths')]
    public function testAnonymousIsSentToTheLogin(string $path)
    {
        $client = static::createClient();
        $client->request('GET', $path);
        $this->assertSame(302, $client->getResponse()->getStatusCode());
        $this->assertStringContainsString('/login', (string)$client->getResponse()->headers->get('Location'));
    }

    /** IsGranted on the controller itself: ROLE_USER is refused even if access_control changed. */
    public function testRoleUserGets403FromTheController()
    {
        self::bootKernel();
        $c = self::getContainer();
        $jan = (new User())->setUsername('jan')->setRole(User::ROLE_USER);
        $admin = new InMemoryUser('admin', 'x', ['ROLE_ADMIN']);
        $listener = $c->get('controller.is_granted_attribute_listener');
        $event = fn() => new ControllerArgumentsEvent(self::$kernel, [$c->get(AuditController::class), 'exportAction'], [new Request()], new Request(), HttpKernelInterface::MAIN_REQUEST);

        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($admin, 'main', $admin->getRoles()));
        $listener->onKernelControllerArguments($event());   // admin passes

        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($jan, 'main', $jan->getRoles()));
        $this->expectException(AccessDeniedException::class);
        $listener->onKernelControllerArguments($event());
    }

    public function testControllersGetTheAuditLogger()
    {
        self::bootKernel();
        foreach ([WhitelistController::class, MyController::class, PluginApiController::class] as $class) {
            $controller = self::getContainer()->get($class);
            $locator = (new \ReflectionProperty($controller, 'container'))->getValue($controller);
            $this->assertTrue($locator->has(AuditLogger::class), $class);
            $this->assertInstanceOf(AuditLogger::class, $locator->get(AuditLogger::class));
        }
    }

    public function testPageRendersEntriesFiltersAndPagination()
    {
        self::bootKernel();
        $c = self::getContainer();
        $request = Request::create('/audit');
        $request->attributes->set('_route', 'antispam_audit_index');
        $request->setSession(new \Symfony\Component\HttpFoundation\Session\Session(new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage()));
        $c->get('request_stack')->push($request);
        $admin = new InMemoryUser('admin', 'x', ['ROLE_ADMIN']);
        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($admin, 'main', $admin->getRoles()));

        $entry = new \AntispamBundle\Entity\AuditLog();
        foreach (['createdAt' => new \DateTime('2026-10-01 12:00'), 'actor' => 'jan', 'actorType' => 'user', 'role' => 'ROLE_USER', 'ip' => '203.0.113.9',
            'action' => 'quarantine.release', 'targetType' => 'message', 'targetId' => '12', 'targetLabel' => '<b>a@b.pl</b>', 'mailbox' => '*',
            'details' => '{"source":"my","ok":true}'] as $k => $v) {
            (new \ReflectionProperty($entry, $k))->setValue($entry, $v);
        }
        $html = $c->get('twig')->render('@Antispam/Audit/index.html.twig', [
            'entries' => [$entry], 'total' => 120, 'page' => 2, 'pages' => 3,
            'filters' => ['from' => null, 'to' => null, 'actor' => 'jan', 'action' => 'quarantine.', 'mailbox' => ''],
            'query' => ['actor' => 'jan', 'action' => 'quarantine.'],
            'actions' => AuditLogger::ACTIONS + ['legacy.thing' => null], 'action_groups' => ['auth.', 'quarantine.'],
            'actor_types' => \AntispamBundle\Entity\AuditLog::ACTOR_TYPES, 'retention' => 365,
        ]);

        $this->assertStringContainsString('Kwarantanna: przywrócenie', $html);
        $this->assertStringContainsString('moja poczta', $html);
        $this->assertStringContainsString('wszystkie skrzynki', $html);
        $this->assertStringContainsString('&lt;b&gt;a@b.pl&lt;/b&gt;', $html, 'labels are escaped');
        $this->assertStringContainsString('/audit/export.csv?actor=jan&amp;action=quarantine.', $html);
        $this->assertStringContainsString('page=3', $html);
        $this->assertStringContainsString('Dziennik audytu', $html, 'nav entry');
    }

    public function testLoginEventsReachTheSubscriberOnTheMainFirewall()
    {
        self::bootKernel();
        $dispatcher = self::getContainer()->get('security.event_dispatcher.main');
        foreach ([LoginSuccessEvent::class, LoginFailureEvent::class, LogoutEvent::class] as $event) {
            $classes = array_map(fn($l) => is_array($l) ? get_class($l[0]) : (is_object($l) ? get_class($l) : ''), $dispatcher->getListeners($event));
            $this->assertContains(AuditSecuritySubscriber::class, $classes, $event);
        }
    }
}
