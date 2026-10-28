<?php

namespace AntispamBundle\Tests\Services\Backup;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Config;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\OAuth\OAuthSettings;

/** OAuth login method, provider secrets and refresh tokens in backups. */
class OAuthBackupTest extends BackupTestCase
{
    private static function seedOAuth($em): void
    {
        self::seed($em);
        $crypto = new CryptoService(self::SECRET);
        $jan = $em->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
        $jan->setImapAuthMethod(Account::AUTH_OAUTH_MICROSOFT)->setOAuthTenant('firma.onmicrosoft.com')
            ->setOAuthRefreshToken($crypto->encrypt('RT-secret'))->setOAuthAccessToken($crypto->encrypt('AT-secret'))
            ->setOAuthUsername('jan@firma.pl')->setOAuthConnectedAt(new \DateTime());
        $em->persist((new Config())->setName(OAuthSettings::KEY_MS_CLIENT_ID)->setValue('client-id'));
        $em->persist((new Config())->setName(OAuthSettings::KEY_MS_CLIENT_SECRET)->setValue($crypto->encrypt('ms-secret')));
        $em->flush();
        $em->clear();
    }

    public function testWithoutSecretsNoTokensOrClientSecret()
    {
        $em = self::em();
        self::seedOAuth($em);
        $json = json_encode(self::exporter($em)->export(false));
        $data = json_decode($json, true);

        $this->assertStringNotContainsString('RT-secret', $json);
        $this->assertStringNotContainsString('oauth_refresh_token', $json);
        $this->assertArrayNotHasKey(OAuthSettings::KEY_MS_CLIENT_SECRET, $data['settings']['config']);
        $this->assertSame('client-id', $data['settings']['config'][OAuthSettings::KEY_MS_CLIENT_ID]);
        $jan = array_column($data['accounts'], null, 'email')['jan@firma.pl'];
        $this->assertSame('oauth_microsoft', $jan['imap_auth_method']);
        $this->assertSame('firma.onmicrosoft.com', $jan['oauth_tenant']);
    }

    public function testWithSecretsRoundTripKeepsTheConsent()
    {
        $source = self::em();
        self::seedOAuth($source);
        $data = self::roundTrip(self::exporter($source)->export(true));
        $json = json_encode($data);
        $this->assertStringNotContainsString('RT-secret', $json, 'sealed with the instance key');
        $this->assertStringNotContainsString('AT-secret', $json);
        $this->assertStringNotContainsString('ms-secret', $json);

        $target = self::em();
        self::importer($target)->import($data, ['settings', 'accounts']);
        $target->clear();
        $crypto = new CryptoService(self::SECRET);
        $jan = $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
        $this->assertTrue($jan->isOAuthConnected());
        $this->assertSame('RT-secret', $crypto->decrypt($jan->getOAuthRefreshToken()));
        $this->assertNull($jan->getOAuthAccessToken(), 'the short-lived access token is refreshed on first use');
        $this->assertSame('firma.onmicrosoft.com', $jan->getOAuthTenant());
        $secret = $target->getRepository(Config::class)->findOneBy(['name' => OAuthSettings::KEY_MS_CLIENT_SECRET]);
        $this->assertTrue($crypto->isEncrypted($secret->getValue()), 'stored encrypted after import');
        $this->assertSame('ms-secret', $crypto->decrypt($secret->getValue()));
    }

    public function testOlderBackupKeepsPasswordLogin()
    {
        $em = self::em();
        self::seed($em);
        $data = self::roundTrip(self::exporter($em)->export(false));
        foreach ($data['accounts'] as &$item) {
            unset($item['imap_auth_method'], $item['oauth_tenant']);
        }
        unset($item);
        $target = self::em();
        self::importer($target)->import($data, ['accounts']);
        $target->clear();
        $this->assertSame(Account::AUTH_PASSWORD, $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl'])->getImapAuthMethod());
    }
}
