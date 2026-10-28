<?php

namespace AntispamBundle\Tests\Services\Doctor;

use AntispamBundle\Command\DoctorCommand;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\CronRun;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\User;
use AntispamBundle\Services\Backup\AppVersion;
use AntispamBundle\Services\ClamavService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\Doctor\DoctorCheck;
use AntispamBundle\Services\Doctor\DoctorService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;

/**
 * antispam:doctor checks against an in-memory SQLite database; the
 * environment-dependent parts (PHP extensions, schema diff, filesystem, disk,
 * ClamAV, DB ping) are stubbed.
 */
class DoctorServiceTest extends TestCase
{
    private const GOOD_SECRET = 'f3a9c1d27b5e48a0b6c2d9e1f4a7b3c5';

    private EntityManager $em;
    private ConfigService $config;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 3) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->config = new ConfigService($this->em);
    }

    /** @param array<string, mixed> $o overrides of the environment / stubs */
    private function doctor(array $o = []): DoctorService
    {
        $clamav = $this->createMock(ClamavService::class);
        $clamav->method('ping')->willReturn($o['clamav_up'] ?? true);

        $doctor = new class(
            $this->em,
            $this->config,
            new CryptoService($o['secret'] ?? self::GOOD_SECRET),
            $clamav,
            new AppVersion(new ParameterBag(['app.version' => '2.0.0']), '/nonexistent'),
            $o['secret'] ?? self::GOOD_SECRET,
            $o['mailer'] ?? 'null://null',
            $o['proxies'] ?? '127.0.0.1',
            $o['admin_hash'] ?? '$2y$04$hash',
            $o['env'] ?? 'prod',
            ['cookie_secure' => $o['cookie_secure'] ?? true],
            '/project',
            '/nonexistent-keys',
        ) extends DoctorService {
            public array $stub = [];

            protected function schemaDiff(): array { return $this->stub['schema'] ?? []; }
            protected function extensionLoaded(string $ext): bool { return !in_array($ext, $this->stub['missing_ext'] ?? [], true); }
            protected function isWritableDir(string $path): bool { return !in_array(basename($path), $this->stub['readonly'] ?? [], true); }
            protected function freeSpace(string $dir): ?float { return $this->stub['free'] ?? 50e9; }
            protected function bundledAgentVersion(): ?string { return '3.0'; }
            protected function pingDatabase(): void
            {
                if (!empty($this->stub['db_down'])) {
                    throw new \RuntimeException('SQLSTATE[HY000] [2002] Connection refused');
                }
            }
        };
        $doctor->stub = $o;

        return $doctor;
    }

    /** @return array<string, DoctorCheck> */
    private function checks(array $o = []): array
    {
        $out = [];
        foreach ($this->doctor($o)->run() as $check) {
            $out[$check->id] = $check;
        }

        return $out;
    }

    private function freshCron(): void
    {
        $this->em->persist(new CronRun('antispam:agent:scan-all'));
        $this->em->flush();
    }

    public function testHealthyInstallHasNoFailuresOrWarnings()
    {
        $this->freshCron();
        $this->config->set('plugin.public_url', 'https://antispam.example.pl');
        $checks = $this->checks();

        foreach ($checks as $id => $check) {
            $this->assertContains($check->status, [DoctorCheck::OK, DoctorCheck::SKIP], $id . ': ' . $check->message);
        }
        $this->assertStringContainsString('2.0.0', $checks['version']->message);
    }

    public function testAppSecret()
    {
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['secret' => 'ChangeMeInProductionPlease'])['app_secret']->status);
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['secret' => ''])['app_secret']->status);
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['secret' => 'short-secret'])['app_secret']->status);
        $this->assertSame(DoctorCheck::WARN, $this->checks(['secret' => str_repeat('ab', 16)])['app_secret']->status);
        $this->assertSame(DoctorCheck::OK, $this->checks()['app_secret']->status);
    }

    public function testMailerRequiredWhenDigestEnabled()
    {
        $this->config->set('digest.enabled', true);
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['mailer' => 'null://null'])['mailer']->status);
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['mailer' => ''])['mailer']->status);
        $this->assertSame(DoctorCheck::OK, $this->checks(['mailer' => 'smtp://u:p@smtp.example.com:587'])['mailer']->status);
    }

    public function testHttpsHintsInProd()
    {
        $this->assertSame(DoctorCheck::WARN, $this->checks(['proxies' => ''])['https']->status);
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['cookie_secure' => 'auto'])['https']->status);
        $this->assertSame(DoctorCheck::SKIP, $this->checks(['env' => 'dev', 'proxies' => ''])['https']->status);
    }

    public function testPublicUrlMustBeHttps()
    {
        $this->config->set('plugin.public_url', 'http://antispam.example.pl');
        $this->assertSame(DoctorCheck::WARN, $this->checks()['public_url']->status);
        $this->config->set('plugin.public_url', 'https://antispam.example.pl');
        $this->assertSame(DoctorCheck::OK, $this->checks()['public_url']->status);
        $this->config->set('plugin.public_url', '');
        $this->assertSame(DoctorCheck::WARN, $this->checks()['public_url']->status, 'plugins enabled by default, no URL');
        $this->config->set('plugin.enabled', '0');
        $this->assertSame(DoctorCheck::OK, $this->checks()['public_url']->status);
    }

    public function testSchemaOutOfSync()
    {
        $check = $this->checks(['schema' => ['ALTER TABLE antispam_account ADD foo INT']])['schema'];
        $this->assertSame(DoctorCheck::FAIL, $check->status);
        $this->assertStringContainsString('doctrine:schema:update', $check->hint);
    }

    public function testCron()
    {
        $this->assertSame(DoctorCheck::WARN, $this->checks()['cron']->status, 'never ran');
        $old = new CronRun('antispam:agent:scan-all');
        (new \ReflectionProperty(CronRun::class, 'startedAt'))->setValue($old, new \DateTime('-3 hours'));
        $this->em->persist($old);
        $this->em->flush();
        $this->assertStringContainsString('stopped', $this->checks()['cron']->message);
        $this->freshCron();
        $this->assertSame(DoctorCheck::OK, $this->checks()['cron']->status);
    }

    public function testAccountsAgentsAndPasswords()
    {
        $crypto = new CryptoService(self::GOOD_SECRET);
        $never = (new Account())->setName('a')->setEmail('never@firma.pl')->setImapHost('imap.firma.pl')->setImapPassword('plain-text');
        $scanned = (new Account())->setName('b')->setEmail('ok@firma.pl')->setImapHost('imap.firma.pl')->setImapPassword($crypto->encrypt('x'));
        $scanned->markScanned(['total' => 1]);
        $oldAgent = (new Account())->setName('c')->setEmail('ssh@firma.pl')->setConnectionType(Account::CONNECTION_SSH)->setAgentDeployed(true);
        $oldAgent->markScanned(['total' => 1, 'agent_version' => '2.5']);
        foreach ([$never, $scanned, $oldAgent] as $a) {
            $this->em->persist($a);
        }
        $this->em->flush();

        $checks = $this->checks();
        $this->assertSame(DoctorCheck::WARN, $checks['accounts_scanned']->status);
        $this->assertStringContainsString('never@firma.pl', $checks['accounts_scanned']->message);
        $this->assertSame(DoctorCheck::WARN, $checks['ssh_agents']->status);
        $this->assertStringContainsString('ssh@firma.pl (2.5)', $checks['ssh_agents']->message);
        $this->assertSame(DoctorCheck::WARN, $checks['stored_passwords']->status);
        $this->assertStringContainsString('never@firma.pl', $checks['stored_passwords']->message);

        // Encrypted with another APP_SECRET: unreadable.
        $scanned->setImapPassword((new CryptoService('another-secret-entirely-1234567'))->encrypt('x'));
        $this->em->flush();
        $this->assertSame(DoctorCheck::FAIL, $this->checks()['stored_passwords']->status);
    }

    public function testRulesOfDeletedMailbox()
    {
        $this->config->set('email', 'biuro@firma.pl');
        $this->em->persist((new Account())->setName('a')->setEmail('jan@firma.pl'));
        $this->em->persist((new Blacklist())->setEmail('*')->setHost('a.example'));
        $this->em->persist((new Blacklist())->setEmail('Jan@Firma.pl')->setHost('b.example'));
        $this->em->persist((new Blacklist())->setEmail('biuro@firma.pl')->setHost('c.example'));
        $this->em->flush();
        $this->assertSame(DoctorCheck::OK, $this->checks()['orphan_rules']->status);

        $this->em->persist((new Blacklist())->setEmail('gone@firma.pl')->setHost('d.example'));
        $this->em->persist((new EmailWhitelist())->setEmail('gone@firma.pl')->setWhitelistemail('x@y.pl'));
        $this->em->flush();
        $check = $this->checks()['orphan_rules'];
        $this->assertSame(DoctorCheck::WARN, $check->status);
        $this->assertStringContainsString('gone@firma.pl: 2', $check->message);
    }

    public function testFeedKeys()
    {
        $this->assertSame(DoctorCheck::SKIP, $this->checks()['feed']->status);
        $this->config->set('feed.enabled', true);
        $this->assertSame(DoctorCheck::WARN, $this->checks()['feed']->status, 'enabled, nothing configured');
        $this->config->set('feed.remote_url', 'https://hub.example.pl');
        $this->assertSame(DoctorCheck::FAIL, $this->checks()['feed']->status, 'hub without key');
        $this->config->set('feed.remote_key', 'hub-key-0123456789');
        $this->assertSame(DoctorCheck::OK, $this->checks()['feed']->status);
    }

    public function testClamavReachability()
    {
        $this->assertSame(DoctorCheck::SKIP, $this->checks(['clamav_up' => false])['clamav']->status);
        $this->config->set('scoring.clamav_enabled', true);
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['clamav_up' => false])['clamav']->status);
        $this->assertSame(DoctorCheck::OK, $this->checks(['clamav_up' => true])['clamav']->status);
    }

    public function testPhpFilesystemDisk()
    {
        $checks = $this->checks(['missing_ext' => ['imap', 'intl'], 'readonly' => ['data'], 'free' => 50e6]);
        $this->assertSame(DoctorCheck::FAIL, $checks['php_extensions']->status);
        $this->assertStringContainsString('imap, intl', $checks['php_extensions']->message);
        $this->assertSame(DoctorCheck::FAIL, $checks['var_writable']->status);
        $this->assertStringContainsString('var/data', $checks['var_writable']->message);
        $this->assertSame(DoctorCheck::FAIL, $checks['disk_space']->status);
        $this->assertSame(DoctorCheck::WARN, $this->checks(['missing_ext' => ['zip']])['php_extensions']->status);
        $this->assertSame(DoctorCheck::WARN, $this->checks(['free' => 500e6])['disk_space']->status);
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['missing_ext' => ['sodium']])['encryption']->status);
    }

    public function testAdminLogin()
    {
        $this->assertSame(DoctorCheck::FAIL, $this->checks(['admin_hash' => ''])['admin_login']->status);
        $this->em->persist((new User())->setUsername('szef')->setPassword('x')->setRole(User::ROLE_ADMIN));
        $this->em->flush();
        $this->assertSame(DoctorCheck::OK, $this->checks(['admin_hash' => ''])['admin_login']->status);
    }

    public function testDatabaseDownSkipsDatabaseChecks()
    {
        $checks = $this->checks(['db_down' => true]);
        $this->assertSame(DoctorCheck::FAIL, $checks['database']->status);
        foreach (['schema', 'cron', 'accounts_scanned', 'orphan_rules', 'clamav'] as $id) {
            $this->assertSame(DoctorCheck::SKIP, $checks[$id]->status, $id);
        }
        $this->assertSame(DoctorCheck::OK, $checks['app_secret']->status, 'other checks still run');
    }

    public function testCommandExitCodes()
    {
        $this->freshCron();
        $this->config->set('plugin.public_url', 'https://antispam.example.pl');
        $tester = new CommandTester(new DoctorCommand($this->doctor()));
        $this->assertSame(Command::SUCCESS, $tester->execute([]));
        $this->assertStringContainsString('0 failure(s)', $tester->getDisplay());

        $tester = new CommandTester(new DoctorCommand($this->doctor(['proxies' => ''])));
        $this->assertSame(Command::SUCCESS, $tester->execute([]), 'warnings alone pass');
        $this->assertSame(Command::FAILURE, $tester->execute(['--strict' => true]));

        $tester = new CommandTester(new DoctorCommand($this->doctor(['secret' => 'ChangeMeInProductionPlease'])));
        $this->assertSame(Command::FAILURE, $tester->execute([]));
        $this->assertStringContainsString('[FAIL] app_secret', $tester->getDisplay());

        $this->assertSame(Command::FAILURE, $tester->execute(['--format' => 'json']));
        $json = json_decode($tester->getDisplay(), true);
        $this->assertFalse($json['ok']);
        $this->assertSame(1, $json['counts']['fail']);
    }
}
