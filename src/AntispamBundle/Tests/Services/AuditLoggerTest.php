<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Command\PurgeCommand;
use AntispamBundle\Controller\AuditController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\User;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\ConfigService;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * AuditLogger against a real (SQLite) table: actor / role / IP resolution,
 * secrets never stored, failures swallowed, purge retention and CSV export.
 */
class AuditLoggerTest extends TestCase
{
    private EntityManager $em;
    private RequestStack $requests;
    private TokenStorage $tokens;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->requests = new RequestStack();
        $this->tokens = new TokenStorage();
    }

    protected function tearDown(): void
    {
        Request::setTrustedProxies([], -1);
    }

    private function logger(?LoggerInterface $log = null, ?Connection $db = null): AuditLogger
    {
        return new AuditLogger($db ?? $this->em->getConnection(), $this->em, $this->requests, $this->tokens, $log ?? new NullLogger());
    }

    private function request(string $ip = '198.51.100.7', array $headers = []): void
    {
        $request = Request::create('/x', 'POST', [], [], [], ['REMOTE_ADDR' => $ip] + $headers);
        $this->requests->push($request);
    }

    /** @return AuditLog[] */
    private function rows(): array
    {
        $this->em->clear();
        return $this->em->getRepository(AuditLog::class)->findBy([], ['id' => 'ASC']);
    }

    private function loginAs(object $user): void
    {
        $this->tokens->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
    }

    public function testRecordsDatabaseUserRoleIpTargetAndDetails()
    {
        $this->request();
        $this->loginAs((new User())->setUsername('jan')->setRole(User::ROLE_USER));

        $this->logger()->log('rule.add', targetType: 'whitelist', targetId: 5, label: 'firma.pl', mailbox: 'jan@firma.pl', details: ['pattern_type' => 'exact']);

        [$row] = $this->rows();
        $this->assertSame('jan', $row->getActor());
        $this->assertSame(AuditLog::ACTOR_USER, $row->getActorType());
        $this->assertSame(User::ROLE_USER, $row->getRole());
        $this->assertSame('198.51.100.7', $row->getIp());
        $this->assertSame('rule.add', $row->getAction());
        $this->assertSame(['whitelist', '5', 'firma.pl', 'jan@firma.pl'], [$row->getTargetType(), $row->getTargetId(), $row->getTargetLabel(), $row->getMailbox()]);
        $this->assertSame(['pattern_type' => 'exact'], $row->getDetailsArray());
        $this->assertEqualsWithDelta(time(), $row->getCreatedAt()->getTimestamp(), 5);
    }

    public function testEnvAdminAnonymousAndCli()
    {
        $this->loginAs(new InMemoryUser('admin', 'x', ['ROLE_ADMIN']));
        $this->logger()->log('settings.save');
        $this->tokens->setToken(null);
        $this->logger()->log('cert.sync');          // no request, no token: console
        $this->request();
        $this->logger()->log('auth.login_failed');  // request, no token: anonymous

        $rows = $this->rows();
        $this->assertSame(['admin', AuditLog::ACTOR_ENV_ADMIN, 'ROLE_ADMIN'], [$rows[0]->getActor(), $rows[0]->getActorType(), $rows[0]->getRole()]);
        $this->assertSame([AuditLog::ACTOR_CLI, null], [$rows[1]->getActorType(), $rows[1]->getIp()]);
        $this->assertSame([AuditLog::ACTOR_ANONYMOUS, null], [$rows[2]->getActorType(), $rows[2]->getRole()]);
    }

    public function testExplicitActorWins()
    {
        $this->request();
        $this->logger()->log('quarantine.release', mailbox: 'jan@firma.pl', actor: 'link z raportu', actorType: AuditLog::ACTOR_DIGEST_LINK);

        [$row] = $this->rows();
        $this->assertSame(['link z raportu', AuditLog::ACTOR_DIGEST_LINK], [$row->getActor(), $row->getActorType()]);
    }

    public function testClientIpHonoursTrustedProxiesOnly()
    {
        // Untrusted proxy: the forged header is ignored.
        $this->request('10.0.0.2', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9']);
        $this->logger()->log('auth.login');
        // Trusted proxy: the real client address.
        Request::setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR);
        $this->logger()->log('auth.login');

        $rows = $this->rows();
        $this->assertSame('10.0.0.2', $rows[0]->getIp());
        $this->assertSame('203.0.113.9', $rows[1]->getIp());
    }

    public function testSecretsAreNeverStored()
    {
        $post = ['enabled' => '1', 'vt_api_key' => 'SECRET-VT-KEY', 'url_gsb_api_key' => '', 'url_gsb_api_key_clear' => '1', 'score' => '6'];
        $this->logger()->log('settings.save', details: AuditLogger::formFields($post, ['vt_api_key', 'url_gsb_api_key']) + [
            'password' => 'hunter2', 'api_key' => 'k', 'remote_key' => 'k2', 'token' => 't', 'nested' => ['secret' => 's', 'ok' => 1],
        ]);

        [$row] = $this->rows();
        $this->assertStringNotContainsString('SECRET-VT-KEY', $row->getDetails());
        $this->assertStringNotContainsString('hunter2', $row->getDetails());
        $this->assertSame([
            'fields' => ['enabled', 'score'],
            'secrets_changed' => ['vt_api_key', 'url_gsb_api_key'],
            'nested' => ['ok' => 1],
        ], $row->getDetailsArray());
    }

    public function testLongValuesAreCut()
    {
        $this->logger()->log(str_repeat('a', 100), label: str_repeat('x', 1000), details: ['big' => str_repeat('y', 5000)]);
        [$row] = $this->rows();
        $this->assertSame(64, mb_strlen($row->getAction()));
        $this->assertSame(255, mb_strlen($row->getTargetLabel()));
        $this->assertLessThan(AuditLogger::MAX_DETAILS_JSON, strlen($row->getDetails()));
    }

    public function testFailedWriteDoesNotThrowAndIsReported()
    {
        $db = $this->createMock(Connection::class);
        $db->method('insert')->willThrowException(new \RuntimeException('table missing'));
        $log = $this->createMock(LoggerInterface::class);
        $log->expects($this->once())->method('error')
            ->with($this->stringContains('Audit log write failed'), $this->callback(fn($ctx) => $ctx['audit_action'] === 'rule.add' && $ctx['error'] === 'table missing'));

        $this->logger($log, $db)->log('rule.add');
        $this->addToAssertionCount(1); // reached: no exception
    }

    public function testFailureOfTheEntityManagerLookupIsHarmless()
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willThrowException(new \RuntimeException('down'));
        $logger = new AuditLogger($this->em->getConnection(), $em, $this->requests, $this->tokens, new NullLogger());

        $logger->quarantine('delete', 'panel', 'imap-3', '9', ['success' => true, 'sender' => '']);
        [$row] = $this->rows();
        $this->assertSame('quarantine.delete', $row->getAction());
        $this->assertNull($row->getMailbox());
    }

    public function testQuarantineResolvesTheMailboxFromTheKey()
    {
        $account = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP);
        $this->em->persist($account);
        $this->em->flush();

        $this->logger()->quarantine('whitelist', 'panel', 'imap-' . $account->getId(), '12', ['success' => true, 'sender' => 'a@b.pl']);
        $this->logger()->quarantine('bogus', 'my', 'ssh-999', '1', ['success' => false]);

        [$ok, $bogus] = $this->rows();
        $this->assertSame(['quarantine.whitelist', 'jan@firma.pl', 'a@b.pl', '12'], [$ok->getAction(), $ok->getMailbox(), $ok->getTargetLabel(), $ok->getTargetId()]);
        $this->assertSame(['source' => 'panel', 'quarantine' => 'imap-' . $account->getId(), 'ok' => true], $ok->getDetailsArray());
        $this->assertSame(['quarantine.unknown', null], [$bogus->getAction(), $bogus->getMailbox()]);
    }

    private function insertAged(string $age): void
    {
        $this->em->getConnection()->insert(AuditLog::TABLE, [
            'created_at' => (new \DateTime($age))->format('Y-m-d H:i:s'),
            'actor' => 'a', 'actor_type' => 'user', 'action' => 'aged ' . $age,
        ]);
    }

    public function testPurgeUsesItsOwnRetention()
    {
        foreach (['-800 days', '-400 days', '-100 days', 'now'] as $age) {
            $this->insertAged($age);
        }
        $config = new ConfigService($this->em);
        $purge = fn(array $in = []) => (new CommandTester(new PurgeCommand($this->em, $config)))->execute($in);

        // --days only concerns the score log.
        $this->assertSame(0, $purge(['--days' => '1', '--dry-run' => true]));
        $this->assertCount(4, $this->rows());

        $this->assertSame(0, $purge());   // default 365 days
        $this->assertSame(['aged -100 days', 'aged now'], array_map(fn($r) => $r->getAction(), $this->rows()));

        $config->set(AuditLogger::CONFIG_RETENTION, '50');
        $purge();
        $this->assertSame(['aged now'], array_map(fn($r) => $r->getAction(), $this->rows()));

        $this->insertAged('-5000 days');
        $config->set(AuditLogger::CONFIG_RETENTION, '0');
        $purge();
        $this->assertCount(2, $this->rows());
    }

    public function testCsvExportFollowsFiltersAndNeutralisesFormulas()
    {
        $this->request();
        $logger = $this->logger();
        $logger->log('rule.add', label: '=HYPERLINK("http://evil")', mailbox: 'jan@firma.pl', actor: 'jan', actorType: AuditLog::ACTOR_USER);
        $logger->log('user.delete', label: 'ola', actor: 'admin', actorType: AuditLog::ACTOR_ENV_ADMIN);

        $controller = new AuditController($this->em, new ConfigService($this->em));
        $response = $controller->exportAction(Request::create('/audit/export.csv', 'GET', ['action' => 'rule.']));
        ob_start();
        $response->sendContent();
        $csv = ob_get_clean();

        $this->assertStringStartsWith("\xEF\xBB\xBF", $csv);
        $this->assertStringContainsString('attachment; filename=dziennik-audytu-', $response->headers->get('Content-Disposition'));
        $this->assertStringContainsString('text/csv', $response->headers->get('Content-Type'));
        $lines = array_values(array_filter(explode("\n", substr($csv, 3))));
        $this->assertCount(2, $lines, 'header + the one rule.* row');
        $this->assertStringStartsWith('czas;aktor;', $lines[0]);
        $this->assertStringContainsString(';jan;user;', $lines[1]);
        $this->assertStringContainsString('"\'=HYPERLINK(""http://evil"")"', $lines[1]);
        $this->assertStringNotContainsString('user.delete', $csv);
    }

    public function testFiltersParsing()
    {
        $f = AuditController::filters(Request::create('/audit', 'GET', [
            'from' => '2026-01-02', 'to' => '2026-01-05', 'actor' => ' jan ', 'action' => "rule.add' OR 1", 'mailbox' => 'firma',
        ]));
        $this->assertSame('2026-01-02 00:00', $f['from']->format('Y-m-d H:i'));
        $this->assertSame('2026-01-06 00:00', $f['to']->format('Y-m-d H:i'), 'end date inclusive');
        $this->assertSame(['jan', '', 'firma'], [$f['actor'], $f['action'], $f['mailbox']]);
        $this->assertNull(AuditController::filters(Request::create('/audit', 'GET', ['from' => 'yesterday']))['from']);
    }

    public function testSearchFiltersAndPagination()
    {
        $logger = $this->logger();
        for ($i = 0; $i < 7; $i++) {
            $logger->log($i % 2 ? 'rule.add' : 'auth.login', mailbox: $i < 3 ? 'jan@firma.pl' : 'ola@firma.pl', actor: 'u' . $i, actorType: AuditLog::ACTOR_USER);
        }
        $repo = $this->em->getRepository(AuditLog::class);

        $page = $repo->search([], 2, 5);
        $this->assertSame(7, $page['total']);
        $this->assertCount(2, $page['items']);
        $this->assertSame(3, $repo->search(['action' => 'rule.add'], 1, 50)['total']);
        $this->assertSame(3, $repo->search(['action' => 'rule.'], 1, 50)['total']);
        $this->assertSame(3, $repo->search(['mailbox' => 'jan@'], 1, 50)['total']);
        $this->assertSame(1, $repo->search(['actor' => 'u4'], 1, 50)['total']);
        $this->assertSame(0, $repo->search(['actor' => '%'], 1, 50)['total'], 'LIKE wildcards are literal');
        $this->assertSame(0, $repo->search(['from' => new \DateTime('+1 day')], 1, 50)['total']);
    }
}
