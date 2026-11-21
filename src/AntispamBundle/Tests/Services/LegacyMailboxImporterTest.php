<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\LegacyMailboxImporter;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;

/**
 * The old single mailbox of the settings page becomes a regular IMAP account
 * at `antispam:db:upgrade`; its config keys are cleared, a second run does nothing.
 */
class LegacyMailboxImporterTest extends TestCase
{
    private EntityManager $em;
    private ConfigService $config;
    private CryptoService $crypto;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->config = new ConfigService($this->em);
        $this->crypto = new CryptoService('test-secret');
    }

    private function importer(): LegacyMailboxImporter
    {
        return new LegacyMailboxImporter($this->em, $this->config, $this->crypto);
    }

    private function legacyMailbox(array $overrides = []): void
    {
        $values = $overrides + [
            'email' => 'Biuro@Firma.pl',
            'login' => 'biuro',
            'password' => $this->crypto->encrypt('tajne-haslo'),
            'imap' => 'imap.firma.pl',
            'imap_port' => '143',
            'imap_flags' => '/imap/tls/novalidate-cert',
            'delete' => '1',
            'digest.imap_recipient' => 'IT@firma.pl',
            'imap.legacy_cursor' => '1700000001:4242:1700000500',
        ];
        foreach ($values as $key => $value) {
            $this->config->set($key, $value);
        }
    }

    /** @return Account[] */
    private function accounts(): array
    {
        $this->em->clear();
        return $this->em->getRepository(Account::class)->findAll();
    }

    public function testImportsTheOldMailboxIntoAnImapAccountAndClearsTheSettings()
    {
        $this->legacyMailbox();
        $this->assertTrue($this->importer()->pending());

        $message = $this->importer()->import();

        $this->assertStringContainsString('biuro@firma.pl przeniesiona do Konta', $message);
        $accounts = $this->accounts();
        $this->assertCount(1, $accounts);
        $a = $accounts[0];
        $this->assertSame(Account::CONNECTION_IMAP, $a->getConnectionType());
        $this->assertSame(['biuro@firma.pl', 'biuro@firma.pl', 'biuro', 'imap.firma.pl', 143, '/imap/tls/novalidate-cert'],
            [$a->getEmail(), $a->getName(), $a->getImapLogin(), $a->getImapHost(), $a->getImapPort(), $a->getImapFlags()]);
        $this->assertTrue($this->crypto->isEncrypted($a->getImapPassword()));
        $this->assertSame('tajne-haslo', $this->crypto->decrypt($a->getImapPassword()));
        $this->assertTrue($a->getDeleteSpam());
        $this->assertSame('it@firma.pl', $a->getDigestRecipient());
        $this->assertSame(['uidvalidity' => 1700000001, 'last_uid' => 4242], $a->getImapCursor());
        $this->assertSame(1700000500, $a->getLastScanAt()->getTimestamp());

        foreach (LegacyMailboxImporter::KEYS as $key) {
            $this->assertSame('', (string)$this->config->get($key), $key . ' cleared');
        }
        $this->assertFalse($this->importer()->pending());
    }

    public function testSecondRunDoesNothing()
    {
        $this->legacyMailbox();
        $this->assertNotNull($this->importer()->import());

        $this->assertNull($this->importer()->import());
        $this->assertCount(1, $this->accounts());
    }

    public function testNothingConfiguredMeansNothingToImport()
    {
        $this->assertFalse($this->importer()->pending());
        $this->assertNull($this->importer()->import());
        $this->assertSame([], $this->accounts());
    }

    public function testPlainPasswordDefaultsAndNoCursor()
    {
        $this->legacyMailbox([
            'email' => '', // address taken from the login
            'login' => 'jan@firma.pl',
            'password' => 'stare-jawne', // stored before encryption existed
            'imap_port' => '',
            'imap_flags' => '',
            'delete' => '',
            'digest.imap_recipient' => 'jan@firma.pl', // same as the mailbox: no override
            'imap.legacy_cursor' => '',
        ]);

        $this->importer()->import();

        $a = $this->accounts()[0];
        $this->assertSame('jan@firma.pl', $a->getEmail());
        $this->assertSame(993, $a->getImapPort());
        $this->assertNotEmpty($a->getImapFlags());
        $this->assertTrue($this->crypto->isEncrypted($a->getImapPassword()), 'a plain stored password is encrypted on the way');
        $this->assertSame('stare-jawne', $this->crypto->decrypt($a->getImapPassword()));
        $this->assertFalse($a->getDeleteSpam());
        $this->assertNull($a->getDigestRecipient());
        $this->assertNull($a->getImapCursor());
        $this->assertNull($a->getLastScanAt());
    }

    public function testExistingAccountWithTheSameAddressOnlyClearsTheSettings()
    {
        $existing = (new Account())->setName('Biuro')->setEmail('biuro@firma.pl')->setConnectionType(Account::CONNECTION_SSH);
        $this->em->persist($existing);
        $this->em->flush();
        $this->legacyMailbox();

        $message = $this->importer()->import();

        $this->assertStringContainsString('jest już w Konta (#' . $existing->getId() . ')', $message);
        $accounts = $this->accounts();
        $this->assertCount(1, $accounts);
        $this->assertSame(Account::CONNECTION_SSH, $accounts[0]->getConnectionType(), 'existing account untouched');
        $this->assertSame('', (string)$this->config->get('imap'));
        $this->assertSame('', (string)$this->config->get('password'));
        $this->assertNull($this->importer()->import());
    }

    public function testMailboxWithoutAnAddressIsNotImported()
    {
        $this->legacyMailbox(['email' => '', 'login' => 'biuro']);

        $this->assertStringContainsString('bez adresu e-mail', $this->importer()->import());
        $this->assertSame([], $this->accounts());
        $this->assertSame('imap.firma.pl', $this->config->get('imap'), 'settings kept for a manual move');
    }
}
