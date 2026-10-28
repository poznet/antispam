<?php

namespace AntispamBundle\Services\OAuth;

use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * OAuth2 protocol for IMAP access (authorization URL with state + PKCE,
 * code exchange, refresh, client credentials) against:
 *  - Microsoft identity platform v2.0 (Entra ID): delegated scope
 *    https://outlook.office.com/IMAP.AccessAsUser.All + offline_access,
 *    app-only scope https://outlook.office365.com/.default;
 *  - Google: scope https://mail.google.com/, access_type=offline.
 *
 * Stateless: tokens are stored by OAuthTokenManager, the pending state by
 * the controller (session).
 */
class OAuthClient
{
    public const MS_LOGIN = 'https://login.microsoftonline.com/';
    public const MS_IMAP_SCOPE = 'https://outlook.office.com/IMAP.AccessAsUser.All';
    public const MS_APP_SCOPE = 'https://outlook.office365.com/.default';
    public const GOOGLE_AUTHORIZE = 'https://accounts.google.com/o/oauth2/v2/auth';
    public const GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';
    public const GOOGLE_IMAP_SCOPE = 'https://mail.google.com/';

    /** Access tokens are renewed this many seconds before they expire. */
    public const EXPIRY_MARGIN = 300;

    public function __construct(private HttpClientInterface $http, private OAuthSettings $settings)
    {
    }

    public static function scopes(string $provider): string
    {
        return $provider === OAuthSettings::GOOGLE
            ? 'openid email ' . self::GOOGLE_IMAP_SCOPE
            : 'openid email profile offline_access ' . self::MS_IMAP_SCOPE;
    }

    /** PKCE (RFC 7636): random verifier (43-128 chars) and its S256 challenge. */
    public static function pkce(): array
    {
        $verifier = self::b64url(random_bytes(48));
        return ['verifier' => $verifier, 'challenge' => self::b64url(hash('sha256', $verifier, true))];
    }

    public static function randomState(): string
    {
        return self::b64url(random_bytes(32));
    }

    public function tokenEndpoint(string $provider, ?string $tenant = null): string
    {
        if ($provider === OAuthSettings::GOOGLE) {
            return self::GOOGLE_TOKEN;
        }
        return self::MS_LOGIN . rawurlencode($this->tenant($tenant)) . '/oauth2/v2.0/token';
    }

    /**
     * URL the admin's browser is redirected to (GET - CSP form-action 'self'
     * would block a cross-origin form post).
     */
    public function authorizationUrl(string $provider, string $redirectUri, string $state, string $codeChallenge, ?string $loginHint = null, ?string $tenant = null): string
    {
        $this->assertConfigured($provider);
        $params = [
            'client_id' => $this->settings->clientId($provider),
            'response_type' => 'code',
            'redirect_uri' => $redirectUri,
            'scope' => self::scopes($provider),
            'state' => $state,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];
        if ($loginHint !== null && $loginHint !== '') {
            $params['login_hint'] = $loginHint;
        }
        if ($provider === OAuthSettings::GOOGLE) {
            // A refresh token is only issued with access_type=offline, and
            // again after the first consent only with prompt=consent.
            $params['access_type'] = 'offline';
            $params['prompt'] = 'consent';
            $params['include_granted_scopes'] = 'true';
            return self::GOOGLE_AUTHORIZE . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
        }
        $params['response_mode'] = 'query';
        $params['prompt'] = 'select_account';
        return self::MS_LOGIN . rawurlencode($this->tenant($tenant)) . '/oauth2/v2.0/authorize?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /** Authorization code -> tokens (+ the address from the id_token). */
    public function exchangeCode(string $provider, string $code, string $verifier, string $redirectUri, ?string $tenant = null): array
    {
        $this->assertConfigured($provider);
        $body = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => $this->settings->clientId($provider),
            'client_secret' => $this->settings->clientSecret($provider),
            'code_verifier' => $verifier,
        ];
        if ($provider === OAuthSettings::MICROSOFT) {
            $body['scope'] = self::scopes($provider);
        }
        $tokens = $this->post($this->tokenEndpoint($provider, $tenant), $body);
        if (($tokens['refresh_token'] ?? '') === '') {
            throw new OAuthException($provider === OAuthSettings::GOOGLE
                ? 'Google nie zwrócił tokenu odświeżania. Usuń dostęp aplikacji na myaccount.google.com/permissions i połącz ponownie.'
                : 'Microsoft nie zwrócił tokenu odświeżania (brak zgody na offline_access).');
        }
        return $tokens;
    }

    public function refresh(string $provider, string $refreshToken, ?string $tenant = null): array
    {
        $this->assertConfigured($provider);
        $body = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->settings->clientId($provider),
            'client_secret' => $this->settings->clientSecret($provider),
        ];
        if ($provider === OAuthSettings::MICROSOFT) {
            $body['scope'] = self::scopes($provider);
        }
        return $this->post($this->tokenEndpoint($provider, $tenant), $body);
    }

    /** Microsoft 365 app-only token (client credentials, no user). */
    public function clientCredentials(?string $tenant = null): array
    {
        $this->assertConfigured(OAuthSettings::MICROSOFT);
        $tenant = $this->tenant($tenant);
        if (!OAuthSettings::isSpecificTenant($tenant)) {
            throw new OAuthException('Logowanie aplikacji (client credentials) wymaga konkretnego tenanta (GUID lub domena), nie "' . $tenant . '". Ustaw go w koncie lub w Ustawienia → Logowanie OAuth.');
        }
        return $this->post($this->tokenEndpoint(OAuthSettings::MICROSOFT, $tenant), [
            'grant_type' => 'client_credentials',
            'client_id' => $this->settings->clientId(OAuthSettings::MICROSOFT),
            'client_secret' => $this->settings->clientSecret(OAuthSettings::MICROSOFT),
            'scope' => self::MS_APP_SCOPE,
        ]);
    }

    /**
     * Address from an id_token received directly from the token endpoint
     * over TLS (OpenID Connect Core 3.1.3.7: the signature check may be
     * skipped then). email, else preferred_username / upn (Microsoft).
     */
    public static function addressFromIdToken(?string $idToken): ?string
    {
        $parts = explode('.', (string)$idToken);
        if (count($parts) < 2) {
            return null;
        }
        $claims = json_decode((string)base64_decode(strtr($parts[1], '-_', '+/'), false), true);
        if (!is_array($claims)) {
            return null;
        }
        foreach (['email', 'preferred_username', 'upn'] as $claim) {
            $v = isset($claims[$claim]) && is_string($claims[$claim]) ? trim($claims[$claim]) : '';
            if ($v !== '' && filter_var($v, FILTER_VALIDATE_EMAIL)) {
                return strtolower($v);
            }
        }
        return null;
    }

    /** expires_in -> absolute expiry (default 1 hour when missing). */
    public static function expiresAt(array $tokens): \DateTimeImmutable
    {
        $in = (int)($tokens['expires_in'] ?? 3600);
        return new \DateTimeImmutable('+' . max(60, min($in, 86400)) . ' seconds');
    }

    private function tenant(?string $tenant): string
    {
        $tenant = trim((string)$tenant);
        $tenant = $tenant !== '' ? $tenant : $this->settings->microsoftTenant();
        if (!OAuthSettings::isValidTenant($tenant)) {
            throw new OAuthException('Nieprawidłowy tenant Microsoft: ' . mb_substr($tenant, 0, 100));
        }
        return $tenant;
    }

    private function assertConfigured(string $provider): void
    {
        if (!in_array($provider, OAuthSettings::PROVIDERS, true)) {
            throw new OAuthException('Nieznany dostawca OAuth.');
        }
        if (!$this->settings->isConfigured($provider)) {
            throw new OAuthException('Logowanie OAuth ' . OAuthSettings::LABELS[$provider] . ' nie jest skonfigurowane - uzupełnij identyfikator i sekret klienta w Ustawienia → Logowanie OAuth.');
        }
    }

    private function post(string $url, array $body): array
    {
        try {
            $response = $this->http->request('POST', $url, [
                'body' => $body,
                'headers' => ['Accept' => 'application/json'],
                'timeout' => 20,
                'max_duration' => 30,
            ]);
            $status = $response->getStatusCode();
            $data = json_decode($response->getContent(false), true);
        } catch (HttpException $e) {
            throw new OAuthException('Brak połączenia z serwerem tokenów OAuth: ' . mb_substr($e->getMessage(), 0, 200), null, $e);
        }
        if (!is_array($data)) {
            throw new OAuthException('Serwer tokenów OAuth zwrócił nieprawidłową odpowiedź (HTTP ' . $status . ').');
        }
        if ($status >= 400 || isset($data['error'])) {
            $code = is_string($data['error'] ?? null) ? $data['error'] : 'http_' . $status;
            $description = is_string($data['error_description'] ?? null) ? $data['error_description'] : '';
            // Microsoft descriptions carry trace / correlation ids on extra lines.
            $description = trim(strtok($description, "\r\n") ?: '');
            $hint = match ($code) {
                'invalid_grant' => ' - token odświeżania wygasł lub został cofnięty, połącz konto ponownie.',
                'invalid_client', 'unauthorized_client' => ' - sprawdź identyfikator i sekret klienta (sekret mógł wygasnąć).',
                'invalid_scope' => ' - aplikacja nie ma uprawnienia IMAP (patrz docs/oauth.md).',
                default => '',
            };
            throw new OAuthException('OAuth: ' . $code . ($description !== '' ? ' (' . mb_substr($description, 0, 250) . ')' : '') . $hint, $code);
        }
        if (!is_string($data['access_token'] ?? null) || $data['access_token'] === '') {
            throw new OAuthException('Serwer tokenów OAuth nie zwrócił tokenu dostępu.');
        }
        return $data;
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
