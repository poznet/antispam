<?php

namespace AntispamBundle\Tests\Services\Backup;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\Config;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\ListSetting;
use AntispamBundle\Entity\User;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\Backup\AppVersion;
use AntispamBundle\Services\Backup\BackupExporter;
use AntispamBundle\Services\Backup\BackupImporter;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;

/** Two in-memory SQLite "instances" for backup round trips. */
abstract class BackupTestCase extends TestCase
{
    public const SECRET = 'source-instance-secret-0123456789abcdef';

    protected static function em(): EntityManager
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 3) . '/Entity'], true);
        $em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($em))->createSchema($em->getMetadataFactory()->getAllMetadata());

        return $em;
    }

    protected static function exporter(EntityManager $em, string $secret = self::SECRET, ?string $version = '9.9.9'): BackupExporter
    {
        return new BackupExporter($em, new CryptoService($secret), new AppVersion(new ParameterBag($version ? ['app.version' => $version] : []), sys_get_temp_dir() . '/no-such-project'));
    }

    protected static function importer(EntityManager $em, string $secret = self::SECRET, string $envAdmin = 'admin'): BackupImporter
    {
        return new BackupImporter($em, new CryptoService($secret), $envAdmin);
    }

    /** A source instance with something in every section. */
    protected static function seed(EntityManager $em, string $secret = self::SECRET): void
    {
        $crypto = new CryptoService($secret);
        $config = new ConfigService($em);
        $config->set('scoring.spam_threshold', 7);
        $config->set('scoring.enabled', true);
        $config->set('plugin.public_url', 'https://antispam.example.pl');
        $config->set('email', 'biuro@firma.pl');
        $config->set('password', $crypto->encrypt('legacy-imap-pass'));
        $config->set('scoring.vt_api_key', 'vt-key-0123456789abcdef');
        $config->set('feed.server_key', 'feed-server-key-0123456789');
        // runtime state - never exported
        $config->set('feed.last_push_id', 1234);
        $config->set('cert.last_sync_at', '2026-10-01T00:00:00+00:00');
        $em->persist((new ListSetting())->setName('impersonation.protected_domains')->setValue("firma.pl\nfirma.com"));

        $em->persist((new Blacklist())->setEmail('*')->setHost('spam.example')->setScore(12)->setCounter(5));
        $em->persist((new Blacklist())->setEmail('jan@firma.pl')->setHost('*.evil.example')->setPatternType('wildcard'));
        $em->persist((new Whitelist())->setEmail('jan@firma.pl')->setHost('partner.pl'));
        $em->persist((new EmailBlacklist())->setEmail('*')->setBlacklistemail('^.*@spam\.ru$')->setPatternType('regex')->setScore(20));
        $em->persist((new EmailWhitelist())->setEmail('*')->setWhitelistemail('szef@firma.pl'));

        $em->persist((new DnsblProvider())->setName('Spamhaus ZEN')->setZone('zen.spamhaus.org')->setScore(6)->setHits(42));

        $imap = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP)
            ->setImapHost('imap.firma.pl')->setImapPort(993)->setImapLogin('jan@firma.pl')
            ->setImapPassword($crypto->encrypt('jan-imap-pass'))->setImapFlags('/imap/ssl')->setDeleteSpam(true);
        $imap->setPluginPassword('plugin-pass');
        $ssh = (new Account())->setName('Serwer')->setEmail('ssh@firma.pl')->setConnectionType(Account::CONNECTION_SSH)
            ->setSshHost('mail.firma.pl')->setSshPort(2222)->setSshUser('vmail')->setSshKeyPath('firma_ed25519')
            ->setMaildirPath('~/Maildir')->setAgentPath('~/antispam-agent')->setSshHostKey('SHA256:abcDEF123+/=')->setAgentDeployed(true);
        $em->persist($imap);
        $em->persist($ssh);

        $em->persist((new User())->setUsername('jan')->setPassword(password_hash('jan-login-pass', PASSWORD_BCRYPT))->setRole(User::ROLE_USER)->setAccounts([$imap]));
        $em->persist((new User())->setUsername('szef')->setPassword(password_hash('szef-login-pass', PASSWORD_BCRYPT))->setRole(User::ROLE_ADMIN));
        $em->flush();
        $em->clear();
    }

    protected static function configValue(EntityManager $em, string $name)
    {
        $row = $em->getRepository(Config::class)->findOneBy(['name' => $name]);

        return $row ? $row->getValue() : null;
    }

    protected static function rowCount(EntityManager $em, string $entity): int
    {
        return (int)$em->createQuery('SELECT COUNT(e.id) FROM ' . $entity . ' e')->getSingleScalarResult();
    }

    /** Export and decode again, as a file on disk would be. */
    protected static function roundTrip(array $data): array
    {
        return json_decode(json_encode($data), true);
    }
}
