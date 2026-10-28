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
use AntispamBundle\Services\Backup\BackupFormat;
use AntispamBundle\Services\Backup\BackupImporter;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;

class BackupRoundTripTest extends BackupTestCase
{
    public function testExportWithoutSecretsLeavesThemOut()
    {
        $em = self::em();
        self::seed($em);
        $data = self::exporter($em)->export(false);
        $json = BackupFormat::encode($data);

        $this->assertSame(BackupFormat::FORMAT, $data['format']);
        $this->assertSame(BackupFormat::SCHEMA_VERSION, $data['schema_version']);
        $this->assertSame('9.9.9', $data['app_version']);
        $this->assertNotEmpty($data['exported_at']);
        $this->assertFalse($data['include_secrets']);
        $this->assertNull($data['secrets']);

        foreach (['legacy-imap-pass', 'jan-imap-pass', 'vt-key-0123456789abcdef', 'feed-server-key', 'enc:v1:', '$2y$', 'firma_ed25519'] as $secret) {
            $this->assertStringNotContainsString($secret, $json, $secret);
        }
        $config = (array)$data['settings']['config'];
        $this->assertSame(7, $config['scoring.spam_threshold']);
        $this->assertArrayNotHasKey('password', $config);
        $this->assertArrayNotHasKey('feed.last_push_id', $config, 'runtime state is not configuration');
        $this->assertArrayNotHasKey('cert.last_sync_at', $config);
        $this->assertArrayNotHasKey('secrets', $data['settings']);
        $this->assertArrayNotHasKey('imap_password', $data['accounts'][0]);
        $this->assertArrayNotHasKey('ssh_key_path', $data['accounts'][1]);
        $this->assertArrayNotHasKey('password_hash', $data['users'][0]);

        $this->assertCount(2, $data['rules']['blacklist']);
        $this->assertSame(['owner' => '*', 'value' => 'spam.example', 'pattern_type' => 'exact', 'score' => 12, 'hits' => 5], $data['rules']['blacklist'][0]);
        $this->assertSame('regex', $data['rules']['email_blacklist'][0]['pattern_type']);
        $this->assertArrayNotHasKey('score', $data['rules']['whitelist'][0]);
        $this->assertSame('zen.spamhaus.org', $data['dnsbl'][0]['zone']);
        $this->assertSame(['jan@firma.pl'], $data['users'][0]['accounts']);
        $this->assertSame('SHA256:abcDEF123+/=', $data['accounts'][1]['ssh_host_key']);
    }

    public function testExportWithSecretsEncryptsEveryOne()
    {
        $em = self::em();
        self::seed($em);
        $data = self::exporter($em)->export(true);
        $json = BackupFormat::encode($data);

        foreach (['legacy-imap-pass', 'jan-imap-pass', 'vt-key-0123456789abcdef', 'feed-server-key-0123456789', 'plugin-pass', '$2y$'] as $plain) {
            $this->assertStringNotContainsString($plain, $json, $plain . ' must be encrypted');
        }
        $crypto = new CryptoService(self::SECRET);
        $this->assertSame(BackupFormat::KEY_CHECK_PLAINTEXT, $crypto->decrypt($data['secrets']['key_check']));
        $secrets = (array)$data['settings']['secrets'];
        $this->assertSame('legacy-imap-pass', $crypto->decrypt($secrets['password']));
        $this->assertSame('vt-key-0123456789abcdef', $crypto->decrypt($secrets['scoring.vt_api_key']));
        $this->assertSame('jan-imap-pass', $crypto->decrypt($data['accounts'][0]['imap_password']));
        $this->assertTrue(password_verify('jan-login-pass', $crypto->decrypt($data['users'][0]['password_hash'])));
        $this->assertSame('firma_ed25519', $data['accounts'][1]['ssh_key_path']);
    }

    public function testRoundTripRecreatesEverything()
    {
        $source = self::em();
        self::seed($source);
        $data = self::roundTrip(self::exporter($source)->export(true));

        $target = self::em();
        $report = self::importer($target)->import($data, BackupFormat::SECTIONS);
        $target->clear();

        $this->assertSame([], array_values(array_filter($report->getWarnings(), fn($w) => !str_contains($w, 'no mailbox'))));
        $this->assertSame(7, self::configValue($target, 'scoring.spam_threshold'));
        $this->assertTrue(self::configValue($target, 'scoring.enabled'));
        $this->assertNull(self::configValue($target, 'feed.last_push_id'));
        $crypto = new CryptoService(self::SECRET);
        $legacy = self::configValue($target, 'password');
        $this->assertTrue($crypto->isEncrypted($legacy), 'the legacy password stays encrypted at rest');
        $this->assertSame('legacy-imap-pass', $crypto->decrypt($legacy));
        $this->assertSame('vt-key-0123456789abcdef', self::configValue($target, 'scoring.vt_api_key'), 'API keys are stored as the forms store them');
        $this->assertSame("firma.pl\nfirma.com", $target->getRepository(ListSetting::class)->findOneBy(['name' => 'impersonation.protected_domains'])->getValue());

        $this->assertSame(2, self::rowCount($target, Blacklist::class));
        $rule = $target->getRepository(Blacklist::class)->findOneBy(['host' => 'spam.example']);
        $this->assertSame(['*', 12, 5], [$rule->getEmail(), $rule->getScore(), $rule->getCounter()]);
        $this->assertSame('wildcard', $target->getRepository(Blacklist::class)->findOneBy(['host' => '*.evil.example'])->getPatternType());
        $this->assertSame(1, self::rowCount($target, Whitelist::class));
        $this->assertSame('^.*@spam\.ru$', $target->getRepository(EmailBlacklist::class)->findOneBy([])->getBlacklistemail());
        $this->assertSame(1, self::rowCount($target, EmailWhitelist::class));
        $this->assertSame(42, $target->getRepository(DnsblProvider::class)->findOneBy(['zone' => 'zen.spamhaus.org'])->getHits());

        $jan = $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
        $this->assertSame('jan-imap-pass', $crypto->decrypt($jan->getImapPassword()));
        $this->assertTrue(password_verify('plugin-pass', $jan->getPluginPasswordHash()));
        $this->assertTrue($jan->getDeleteSpam());
        $ssh = $target->getRepository(Account::class)->findOneBy(['email' => 'ssh@firma.pl']);
        $this->assertSame(['mail.firma.pl', 2222, 'vmail', 'firma_ed25519', 'SHA256:abcDEF123+/=', true],
            [$ssh->getSshHost(), $ssh->getSshPort(), $ssh->getSshUser(), $ssh->getSshKeyPath(), $ssh->getSshHostKey(), $ssh->getAgentDeployed()]);
        $this->assertNull($ssh->getLastScanAt());

        $user = $target->getRepository(User::class)->findOneBy(['username' => 'jan']);
        $this->assertSame(User::ROLE_USER, $user->getRole());
        $this->assertSame(['jan@firma.pl'], array_map(fn($a) => $a->getEmail(), $user->getAccounts()->toArray()));
        $this->assertTrue(password_verify('jan-login-pass', $user->getPassword()));

        // Importing the same file again changes nothing.
        $again = self::importer($target)->import($data, BackupFormat::SECTIONS);
        $this->assertFalse($again->hasChanges(), json_encode($again->getCounts()));
        $this->assertGreaterThan(10, $again->total('unchanged'));
    }

    public function testSecretsFromAnotherAppSecretAreSkipped()
    {
        $source = self::em();
        self::seed($source);
        $data = self::roundTrip(self::exporter($source)->export(true));

        $target = self::em();
        $report = self::importer($target, 'a-completely-different-app-secret-value')->import($data, BackupFormat::SECTIONS);
        $target->clear();

        $this->assertStringContainsString('another APP_SECRET', implode("\n", $report->getWarnings()));
        $this->assertNull(self::configValue($target, 'password'));
        $this->assertNull(self::configValue($target, 'scoring.vt_api_key'));
        $jan = $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
        $this->assertNotNull($jan, 'the account itself is imported');
        $this->assertNull($jan->getImapPassword());
        $user = $target->getRepository(User::class)->findOneBy(['username' => 'jan']);
        $this->assertFalse(password_verify('jan-login-pass', $user->getPassword()), 'a new user gets an unusable random password');
        $this->assertStringContainsString('created without a password', implode("\n", $report->getWarnings()));
    }

    public function testSecretsAreNeverOverwrittenWithEmptyValues()
    {
        $target = self::em();
        self::seed($target);
        $crypto = new CryptoService(self::SECRET);

        // A file without secrets, and one whose secrets are empty.
        $noSecrets = self::roundTrip(self::exporter(self::seededEm())->export(false));
        $emptySecrets = self::roundTrip(self::exporter(self::seededEm())->export(true));
        $emptySecrets['accounts'][0]['imap_password'] = '';
        $emptySecrets['users'][0]['password_hash'] = null;
        $emptySecrets['settings']['secrets']['scoring.vt_api_key'] = '';

        foreach ([$noSecrets, $emptySecrets] as $data) {
            self::importer($target)->import($data, BackupFormat::SECTIONS, BackupImporter::MODE_REPLACE);
            $target->clear();
            $jan = $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
            $this->assertSame('jan-imap-pass', $crypto->decrypt($jan->getImapPassword()));
            $this->assertSame('vt-key-0123456789abcdef', self::configValue($target, 'scoring.vt_api_key'));
            $this->assertSame('legacy-imap-pass', $crypto->decrypt(self::configValue($target, 'password')), 'replace never deletes secrets');
            $this->assertTrue(password_verify('jan-login-pass', $target->getRepository(User::class)->findOneBy(['username' => 'jan'])->getPassword()));
        }
    }

    public function testMergeKeepsExtrasReplaceDeletesThem()
    {
        $source = self::em();
        self::seed($source);
        $data = self::roundTrip(self::exporter($source)->export(false));

        foreach ([BackupImporter::MODE_MERGE => 1, BackupImporter::MODE_REPLACE => 0] as $mode => $extrasLeft) {
            $target = self::em();
            self::seed($target);
            $target->persist((new Blacklist())->setEmail('*')->setHost('local-only.example'));
            $target->persist((new DnsblProvider())->setName('Local')->setZone('local.dnsbl.example'));
            $target->persist((new Account())->setName('Extra')->setEmail('extra@firma.pl')->setImapHost('imap.firma.pl'));
            $target->persist((new User())->setUsername('extra')->setPassword('x')->setRole(User::ROLE_USER));
            $target->persist((new User())->setUsername('runner')->setPassword('x')->setRole(User::ROLE_ADMIN));
            $target->persist((new ListSetting())->setName('local.list')->setValue('x'));
            (new ConfigService($target))->set('local.only', 'x');
            (new ConfigService($target))->set('scoring.spam_threshold', 3);
            $target->flush();
            $janId = $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl'])->getId();
            $target->clear();

            $report = self::importer($target)->import($data, BackupFormat::SECTIONS, $mode, false, 'runner');
            $target->clear();

            $this->assertSame(7, self::configValue($target, 'scoring.spam_threshold'), $mode . ': changed value updated');
            $this->assertSame($extrasLeft, self::rowCount($target, Blacklist::class) - 2, $mode);
            $this->assertSame($extrasLeft, self::rowCount($target, DnsblProvider::class) - 1, $mode);
            $this->assertSame($extrasLeft, self::rowCount($target, Account::class) - 2, $mode);
            $this->assertSame($extrasLeft ? 'x' : null, self::configValue($target, 'local.only'), $mode);
            $this->assertSame($extrasLeft, self::rowCount($target, ListSetting::class) - 1, $mode);
            $this->assertNotNull($target->getRepository(User::class)->findOneBy(['username' => 'runner']), $mode . ': the admin running the import is kept');
            $this->assertSame($extrasLeft, $target->getRepository(User::class)->count(['username' => 'extra']), $mode);
            // state and secrets survive replace; matched records keep their ids
            $this->assertSame(1234, self::configValue($target, 'feed.last_push_id'), $mode);
            $this->assertSame('vt-key-0123456789abcdef', self::configValue($target, 'scoring.vt_api_key'), $mode);
            $this->assertSame($janId, $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl'])->getId(), $mode);
            $this->assertSame($mode === BackupImporter::MODE_REPLACE ? 6 : 0, $report->total('deleted'), $mode);
        }
    }

    public function testDryRunWritesNothing()
    {
        $source = self::em();
        self::seed($source);
        $data = self::roundTrip(self::exporter($source)->export(true));

        $target = self::em();
        $target->persist((new Blacklist())->setEmail('*')->setHost('local-only.example'));
        $target->flush();
        $target->clear();

        $report = self::importer($target)->import($data, BackupFormat::SECTIONS, BackupImporter::MODE_REPLACE, true);
        $target->clear();

        $this->assertTrue($report->dryRun);
        $this->assertSame(2, $report->getCounts()['accounts']['created']);
        $this->assertSame(2, $report->getCounts()['users']['created']);
        $this->assertSame(2, $report->getCounts()['rules']['created'] - 3);
        $this->assertSame(1, $report->getCounts()['rules']['deleted']);
        $this->assertStringNotContainsString('does not exist here', implode("\n", $report->getWarnings()), 'accounts created by the same import count as known');
        foreach ([Config::class, ListSetting::class, Whitelist::class, EmailBlacklist::class, EmailWhitelist::class, DnsblProvider::class, Account::class, User::class] as $entity) {
            $this->assertSame(0, self::rowCount($target, $entity), $entity);
        }
        $this->assertSame(1, self::rowCount($target, Blacklist::class));
    }

    public function testOnlySelectedSectionsAreImported()
    {
        $source = self::em();
        self::seed($source);
        $data = self::roundTrip(self::exporter($source)->export(false));

        $target = self::em();
        $report = self::importer($target)->import($data, BackupFormat::parseOnly('rules, dnsbl'));

        $this->assertSame(['rules', 'dnsbl'], $report->sections);
        $this->assertSame(5, self::rowCount($target, Blacklist::class) + self::rowCount($target, Whitelist::class) + self::rowCount($target, EmailBlacklist::class) + self::rowCount($target, EmailWhitelist::class));
        $this->assertSame(1, self::rowCount($target, DnsblProvider::class));
        $this->assertSame(0, self::rowCount($target, Account::class));
        $this->assertSame(0, self::rowCount($target, Config::class));
    }

    public function testInvalidEntriesAreSkippedNotImported()
    {
        $data = self::roundTrip(self::exporter(self::em())->export(false));
        $data['rules']['blacklist'][] = ['owner' => '*', 'value' => '(a+)+$', 'pattern_type' => 'regex', 'score' => 5];
        $data['rules']['blacklist'][] = ['owner' => '*', 'value' => 'ok.example', 'pattern_type' => 'nonsense'];
        $data['rules']['blacklist'][] = ['owner' => '', 'value' => 'x.example'];
        $data['rules']['blacklist'][] = ['owner' => '*', 'value' => 'Good.Example'];
        $data['rules']['blacklist'][] = ['owner' => '*', 'value' => 'good.example'];
        $data['rules']['unknown_list'] = [['owner' => '*', 'value' => 'x']];
        $data['dnsbl'][] = ['zone' => 'bad zone; rm -rf', 'name' => 'x'];
        $data['accounts'][] = ['email' => 'evil@firma.pl', 'connection_type' => 'imap', 'imap_host' => 'imap.example.pl; touch /tmp/x'];
        $data['accounts'][] = ['email' => 'not-an-email', 'connection_type' => 'imap', 'imap_host' => 'imap.example.pl'];
        $data['users'][] = ['username' => 'admin', 'role' => 'ROLE_ADMIN'];
        $data['users'][] = ['username' => 'boss', 'role' => 'ROLE_SUPER_ADMIN'];
        $data['users'][] = ['username' => 'jan', 'role' => 'ROLE_USER', 'accounts' => ['nobody@firma.pl']];
        $data['settings']['config'] = ['plugin.public_url' => 'javascript:alert(1)', 'password' => 'plain', 'feed.last_push_id' => 99, 'ok.key' => ['nested']];

        $target = self::em();
        $report = self::importer($target)->import($data, BackupFormat::SECTIONS);
        $target->clear();
        $warnings = implode("\n", $report->getWarnings());

        $this->assertSame(['good.example'], array_map(fn($r) => $r->getHost(), $target->getRepository(Blacklist::class)->findAll()));
        $this->assertStringContainsString('duplicate in the file', $warnings);
        $this->assertStringContainsString('Unknown rule list', $warnings);
        $this->assertSame(0, self::rowCount($target, DnsblProvider::class));
        $this->assertSame(0, self::rowCount($target, Account::class));
        $this->assertSame(['jan'], array_map(fn($u) => $u->getUsername(), $target->getRepository(User::class)->findAll()));
        $this->assertStringContainsString('reserved', $warnings);
        $this->assertStringContainsString('nobody@firma.pl does not exist here', $warnings);
        $this->assertSame(0, self::rowCount($target, Config::class));
        $this->assertSame(4 + 4, $report->getCounts()['settings']['skipped'] + $report->getCounts()['rules']['skipped']);
    }

    private static function seededEm()
    {
        $em = self::em();
        self::seed($em);

        return $em;
    }
}
