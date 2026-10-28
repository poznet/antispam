<?php

namespace AntispamBundle\Tests\Services\OAuth;

use AntispamBundle\Services\OAuth\OAuthClient;
use AntispamBundle\Services\OAuth\OAuthException;
use AntispamBundle\Services\OAuth\OAuthSettings;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

class OAuthClientTest extends OAuthTestCase
{
    /** @var array<int, array{method:string, url:string, body:array}> */
    private array $requests = [];

    private function client(MockResponse ...$responses): OAuthClient
    {
        $queue = $responses;
        $http = new MockHttpClient(function ($method, $url, $options) use (&$queue) {
            parse_str((string)($options['body'] ?? ''), $body);
            $this->requests[] = ['method' => $method, 'url' => $url, 'body' => $body];
            return array_shift($queue) ?? new MockResponse('{}', ['http_code' => 500]);
        });
        return new OAuthClient($http, $this->settings());
    }

    private static function json(array $data, int $code = 200): MockResponse
    {
        return new MockResponse(json_encode($data), ['http_code' => $code, 'response_headers' => ['content-type' => 'application/json']]);
    }

    public function testPkceChallengeIsS256OfTheVerifier()
    {
        $p = OAuthClient::pkce();
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43,128}$/', $p['verifier']);
        $this->assertSame(rtrim(strtr(base64_encode(hash('sha256', $p['verifier'], true)), '+/', '-_'), '='), $p['challenge']);
        $this->assertNotSame(OAuthClient::pkce()['verifier'], $p['verifier']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', OAuthClient::randomState());
    }

    public function testMicrosoftAuthorizationUrl()
    {
        $url = $this->client()->authorizationUrl(OAuthSettings::MICROSOFT, 'https://as.example.pl/account/oauth/callback', 'STATE', 'CHALLENGE', 'jan@firma.pl');
        $parts = parse_url($url);
        parse_str($parts['query'], $q);
        $this->assertSame('login.microsoftonline.com', $parts['host']);
        $this->assertSame('/contoso.onmicrosoft.com/oauth2/v2.0/authorize', $parts['path']);
        $this->assertSame('ms-client-id', $q['client_id']);
        $this->assertSame('code', $q['response_type']);
        $this->assertSame('https://as.example.pl/account/oauth/callback', $q['redirect_uri']);
        $this->assertSame('STATE', $q['state']);
        $this->assertSame('CHALLENGE', $q['code_challenge']);
        $this->assertSame('S256', $q['code_challenge_method']);
        $this->assertSame('query', $q['response_mode']);
        $this->assertSame('jan@firma.pl', $q['login_hint']);
        $this->assertContains('https://outlook.office.com/IMAP.AccessAsUser.All', explode(' ', $q['scope']));
        $this->assertContains('offline_access', explode(' ', $q['scope']));
        $this->assertStringNotContainsString('ms-secret', $url);
    }

    public function testPerAccountTenantOverridesTheGlobalOne()
    {
        $url = $this->client()->authorizationUrl(OAuthSettings::MICROSOFT, 'https://x/cb', 's', 'c', null, '11111111-2222-3333-4444-555555555555');
        $this->assertStringStartsWith('https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize?', $url);
    }

    public function testGoogleAuthorizationUrlAsksForOfflineAccess()
    {
        $url = $this->client()->authorizationUrl(OAuthSettings::GOOGLE, 'https://x/cb', 's', 'c');
        parse_str(parse_url($url, PHP_URL_QUERY), $q);
        $this->assertStringStartsWith('https://accounts.google.com/o/oauth2/v2/auth?', $url);
        $this->assertSame('offline', $q['access_type']);
        $this->assertSame('consent', $q['prompt']);
        $this->assertContains('https://mail.google.com/', explode(' ', $q['scope']));
        $this->assertSame('g-client.apps.googleusercontent.com', $q['client_id']);
    }

    public function testNotConfiguredProviderIsRefused()
    {
        unset($this->config[OAuthSettings::KEY_GOOGLE_CLIENT_SECRET]);
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('nie jest skonfigurowane');
        $this->client()->authorizationUrl(OAuthSettings::GOOGLE, 'https://x/cb', 's', 'c');
    }

    public function testExchangeCodeSendsVerifierAndSecret()
    {
        $client = $this->client(self::json(['access_token' => 'AT', 'refresh_token' => 'RT', 'expires_in' => 3599, 'id_token' => self::idToken(['preferred_username' => 'Jan@Firma.pl'])]));
        $tokens = $client->exchangeCode(OAuthSettings::MICROSOFT, 'CODE', 'VERIFIER', 'https://x/cb');
        $this->assertSame('RT', $tokens['refresh_token']);
        $this->assertSame('https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token', $this->requests[0]['url']);
        $this->assertSame('POST', $this->requests[0]['method']);
        $body = $this->requests[0]['body'];
        $this->assertSame(['authorization_code', 'CODE', 'https://x/cb', 'ms-client-id', 'ms-secret', 'VERIFIER'],
            [$body['grant_type'], $body['code'], $body['redirect_uri'], $body['client_id'], $body['client_secret'], $body['code_verifier']]);
        $this->assertSame('jan@firma.pl', OAuthClient::addressFromIdToken($tokens['id_token']));
    }

    public function testExchangeWithoutRefreshTokenFails()
    {
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('tokenu odświeżania');
        $this->client(self::json(['access_token' => 'AT', 'expires_in' => 3600]))->exchangeCode(OAuthSettings::GOOGLE, 'c', 'v', 'https://x/cb');
    }

    public function testRefreshAndErrorMapping()
    {
        $client = $this->client(
            self::json(['access_token' => 'AT2', 'expires_in' => 3600]),
            self::json(['error' => 'invalid_grant', 'error_description' => "AADSTS70008: The refresh token has expired.\r\nTrace ID: abc"], 400),
        );
        $this->assertSame('AT2', $client->refresh(OAuthSettings::GOOGLE, 'RT')['access_token']);
        $this->assertSame('https://oauth2.googleapis.com/token', $this->requests[0]['url']);
        $this->assertSame(['refresh_token', 'RT'], [$this->requests[0]['body']['grant_type'], $this->requests[0]['body']['refresh_token']]);

        try {
            $client->refresh(OAuthSettings::MICROSOFT, 'RT');
            $this->fail('expected invalid_grant');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_grant', $e->oauthError);
            $this->assertTrue($e->needsReconnect());
            $this->assertStringContainsString('AADSTS70008', $e->getMessage());
            $this->assertStringNotContainsString('Trace ID', $e->getMessage());
            $this->assertStringNotContainsString('ms-secret', $e->getMessage());
        }
    }

    public function testClientCredentialsNeedsASpecificTenant()
    {
        $client = $this->client(self::json(['access_token' => 'APP', 'expires_in' => 3600]));
        $this->assertSame('APP', $client->clientCredentials()['access_token']);
        $this->assertSame('client_credentials', $this->requests[0]['body']['grant_type']);
        $this->assertSame('https://outlook.office365.com/.default', $this->requests[0]['body']['scope']);

        $this->config[OAuthSettings::KEY_MS_TENANT] = '';
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('konkretnego tenanta');
        $this->client()->clientCredentials();
    }

    public function testIdTokenWithoutAddress()
    {
        $this->assertNull(OAuthClient::addressFromIdToken(null));
        $this->assertNull(OAuthClient::addressFromIdToken('garbage'));
        $this->assertNull(OAuthClient::addressFromIdToken(self::idToken(['sub' => '123', 'email' => 'not-an-address'])));
        $this->assertSame('a@gmail.com', OAuthClient::addressFromIdToken(self::idToken(['email' => 'a@gmail.com'])));
    }

    public function testInvalidTenantIsRejected()
    {
        $this->assertFalse(OAuthSettings::isValidTenant('evil/../x'));
        $this->assertTrue(OAuthSettings::isValidTenant('organizations'));
        $this->assertFalse(OAuthSettings::isSpecificTenant('common'));
        $this->expectException(OAuthException::class);
        $this->client()->authorizationUrl(OAuthSettings::MICROSOFT, 'https://x/cb', 's', 'c', null, 'a?b=c');
    }
}
