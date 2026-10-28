<?php

namespace AntispamBundle\Tests\Services\OAuth;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\OAuth\OAuthClient;
use AntispamBundle\Services\OAuth\OAuthException;
use AntispamBundle\Services\OAuth\OAuthTokenManager;
use AntispamBundle\Tests\Support\RecordingAuditLogger;
use Doctrine\DBAL\Connection;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

class OAuthTokenManagerTest extends OAuthTestCase
{
    private array $bodies = [];
    private array $updates = [];
    private RecordingAuditLogger $audit;
    private string $locks;

    protected function setUp(): void
    {
        parent::setUp();
        $this->audit = new RecordingAuditLogger();
        $this->locks = sys_get_temp_dir() . '/antispam-oauth-locks-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->locks));
    }

    private function manager(array $responses, ?array $row = null): OAuthTokenManager
    {
        $http = new MockHttpClient(function ($method, $url, $options) use (&$responses) {
            parse_str((string)($options['body'] ?? ''), $body);
            $this->bodies[] = $body;
            return array_shift($responses) ?? new MockResponse('{}', ['http_code' => 500]);
        });
        $db = $this->createMock(Connection::class);
        $db->method('update')->willReturnCallback(function ($table, $data, $where) {
            $this->updates[] = [$table, $data, $where];
            return 1;
        });
        $db->method('fetchAssociative')->willReturn($row ?? false);
        $doctrine = $this->createMock(ManagerRegistry::class);
        $doctrine->method('getConnection')->willReturn($db);

        return new OAuthTokenManager(new OAuthClient($http, $this->settings()), $this->crypto, $doctrine, $this->audit, null, $this->locks);
    }

    private static function json(array $data, int $code = 200): MockResponse
    {
        return new MockResponse(json_encode($data), ['http_code' => $code]);
    }

    private function connected(string $method = Account::AUTH_OAUTH_MICROSOFT): Account
    {
        $a = $this->account($method);
        $a->setOAuthRefreshToken($this->crypto->encrypt('RT-1'))->setOAuthConnectedAt(new \DateTime());
        return $a;
    }

    public function testValidStoredTokenIsReusedWithoutHttp()
    {
        $a = $this->connected()->setOAuthAccessToken($this->crypto->encrypt('AT-stored'))->setOAuthTokenExpiresAt(new \DateTime('+30 minutes'));
        $this->assertSame('AT-stored', $this->manager([])->getAccessToken($a));
        $this->assertSame([], $this->bodies);
    }

    public function testExpiringTokenIsRefreshedAndTheRotatedRefreshTokenStored()
    {
        $a = $this->connected()->setOAuthAccessToken($this->crypto->encrypt('AT-old'))->setOAuthTokenExpiresAt(new \DateTime('+2 minutes'));
        $token = $this->manager([self::json(['access_token' => 'AT-new', 'refresh_token' => 'RT-2', 'expires_in' => 3600])])->getAccessToken($a);

        $this->assertSame('AT-new', $token);
        $this->assertSame('RT-1', $this->bodies[0]['refresh_token']);
        $this->assertSame('RT-2', $this->crypto->decrypt($a->getOAuthRefreshToken()));
        [$table, $data, $where] = $this->updates[0];
        $this->assertSame(['antispam_account', ['id' => 5]], [$table, $where]);
        $this->assertTrue($this->crypto->isEncrypted($data['oauth_access_token']), 'tokens are stored encrypted');
        $this->assertSame('RT-2', $this->crypto->decrypt($data['oauth_refresh_token']));
        $this->assertNull($data['oauth_error']);
        $this->assertGreaterThan(time() + 3000, $a->getOAuthTokenExpiresAt()->getTimestamp());
    }

    /** Another process refreshed while we waited for the lock: its token is used, no second refresh. */
    public function testTokenRefreshedByAnotherProcessIsReused()
    {
        $a = $this->connected()->setOAuthTokenExpiresAt(new \DateTime('-1 minute'));
        $row = [
            'oauth_access_token' => $this->crypto->encrypt('AT-other'),
            'oauth_token_expires_at' => (new \DateTime('+50 minutes'))->format('Y-m-d H:i:s'),
            'oauth_refresh_token' => $this->crypto->encrypt('RT-other'),
        ];
        $this->assertSame('AT-other', $this->manager([], $row)->getAccessToken($a));
        $this->assertSame([], $this->bodies);
    }

    public function testRefreshFailureIsStoredAndAuditedOnce()
    {
        $a = $this->connected()->setOAuthTokenExpiresAt(new \DateTime('-1 minute'));
        $manager = $this->manager([
            self::json(['error' => 'invalid_grant', 'error_description' => 'Token has been expired or revoked.'], 400),
            self::json(['error' => 'invalid_grant', 'error_description' => 'Token has been expired or revoked.'], 400),
        ]);
        foreach ([1, 2] as $attempt) {
            try {
                $manager->getAccessToken($a);
                $this->fail('expected a failure');
            } catch (OAuthException $e) {
                $this->assertTrue($e->needsReconnect());
            }
        }
        $this->assertStringContainsString('invalid_grant', (string)$a->getOAuthError());
        $this->assertNotNull($a->getOAuthErrorAt());
        $this->assertSame('invalid_grant', $this->audit->entries[0]['details']['error_code']);
        $this->assertSame('account.oauth_refresh_failed', $this->audit->entries[0]['action']);
        $this->assertCount(1, $this->audit->entries, 'the same error is audited once, not every cron tick');
        $this->assertStringContainsString('invalid_grant', $this->updates[0][1]['oauth_error']);
    }

    public function testSuccessClearsAPreviousError()
    {
        $a = $this->connected()->setOAuthError('old error');
        $this->manager([self::json(['access_token' => 'AT', 'expires_in' => 3600])])->getAccessToken($a);
        $this->assertNull($a->getOAuthError());
        $this->assertSame('RT-1', $this->crypto->decrypt($a->getOAuthRefreshToken()), 'Google keeps the refresh token');
    }

    public function testAppOnlyUsesClientCredentials()
    {
        $a = $this->account(Account::AUTH_OAUTH_MICROSOFT_APP)->setOAuthTenant('11111111-2222-3333-4444-555555555555');
        $this->assertTrue($a->isOAuthConnected());
        $this->assertSame('APP', $this->manager([self::json(['access_token' => 'APP', 'expires_in' => 3599])])->getAccessToken($a));
        $this->assertSame('client_credentials', $this->bodies[0]['grant_type']);
        $this->assertArrayNotHasKey('oauth_refresh_token', $this->updates[0][1]);
    }

    public function testNotConnectedAccount()
    {
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('nie jest połączone');
        $this->manager([])->getAccessToken($this->account(Account::AUTH_OAUTH_GOOGLE));
    }

    public function testStoreConsentAndDisconnect()
    {
        $a = $this->account(Account::AUTH_OAUTH_GOOGLE)->setOAuthError('x');
        $this->manager([])->storeConsent($a, ['access_token' => 'AT', 'refresh_token' => 'RT', 'expires_in' => 3600], 'jan@gmail.com');
        $this->assertTrue($a->isOAuthConnected());
        $this->assertNull($a->getOAuthError());
        $this->assertSame('jan@gmail.com', $a->getOAuthUsername());
        $this->assertSame('RT', $this->crypto->decrypt($a->getOAuthRefreshToken()));

        // Switching the login method forgets the tokens.
        $a->setImapAuthMethod(Account::AUTH_OAUTH_MICROSOFT);
        $this->assertFalse($a->isOAuthConnected());
        $this->assertNull($a->getOAuthAccessToken());
    }

    public function testAccountLoginMethodDefaults()
    {
        $a = (new Account())->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP);
        $this->assertSame(Account::AUTH_PASSWORD, $a->getImapAuthMethod());
        $this->assertFalse($a->isOAuth());
        $a->setImapAuthMethod('bogus');
        $this->assertSame(Account::AUTH_PASSWORD, $a->getImapAuthMethod());
        $a->setImapAuthMethod(Account::AUTH_OAUTH_GOOGLE)->setOAuthUsername('jan@gmail.com');
        $this->assertSame('google', $a->getOAuthProvider());
        $this->assertSame('jan@gmail.com', $a->getOAuthImapUser(), 'no login: the consented address');
        $a->setImapLogin('shared@firma.pl');
        $this->assertSame('shared@firma.pl', $a->getOAuthImapUser());
        $a->setConnectionType(Account::CONNECTION_SSH);
        $this->assertFalse($a->isOAuth(), 'SSH accounts never use OAuth');
    }
}
