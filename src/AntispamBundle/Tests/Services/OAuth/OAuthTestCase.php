<?php

namespace AntispamBundle\Tests\Services\OAuth;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\OAuth\OAuthSettings;
use PHPUnit\Framework\TestCase;

abstract class OAuthTestCase extends TestCase
{
    protected CryptoService $crypto;
    /** @var array<string, mixed> */
    protected array $config = [];

    protected function setUp(): void
    {
        $this->crypto = new CryptoService('test-secret-for-oauth-tests');
        $this->config = [
            OAuthSettings::KEY_MS_CLIENT_ID => 'ms-client-id',
            OAuthSettings::KEY_MS_CLIENT_SECRET => $this->crypto->encrypt('ms-secret'),
            OAuthSettings::KEY_MS_TENANT => 'contoso.onmicrosoft.com',
            OAuthSettings::KEY_GOOGLE_CLIENT_ID => 'g-client.apps.googleusercontent.com',
            OAuthSettings::KEY_GOOGLE_CLIENT_SECRET => $this->crypto->encrypt('g-secret'),
        ];
    }

    protected function settings(): OAuthSettings
    {
        $config = $this->createMock(ConfigService::class);
        $config->method('get')->willReturnCallback(fn($k) => $this->config[$k] ?? null);
        $config->method('set')->willReturnCallback(function ($k, $v) {
            $this->config[$k] = $v;
            return true;
        });
        return new OAuthSettings($config, $this->crypto);
    }

    protected function account(string $method = Account::AUTH_OAUTH_MICROSOFT, int $id = 5): Account
    {
        $a = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP)->setImapAuthMethod($method);
        (new \ReflectionProperty(Account::class, 'id'))->setValue($a, $id);
        return $a;
    }

    protected static function idToken(array $claims): string
    {
        $b64 = static fn ($v) => rtrim(strtr(base64_encode(json_encode($v)), '+/', '-_'), '=');
        return $b64(['alg' => 'none']) . '.' . $b64($claims) . '.sig';
    }
}
