<?php

namespace AntispamBundle\Services\OAuth;

use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;

/**
 * Global OAuth app settings (Ustawienia → Logowanie OAuth, `config` table).
 * Client secrets are stored encrypted with CryptoService.
 *
 * One app registration per provider serves every mailbox: an Entra app
 * (Microsoft 365) and a Google Cloud OAuth client (Gmail / Workspace).
 */
class OAuthSettings
{
    public const MICROSOFT = 'microsoft';
    public const GOOGLE = 'google';
    public const PROVIDERS = [self::MICROSOFT, self::GOOGLE];

    public const KEY_MS_CLIENT_ID = 'oauth.microsoft.client_id';
    public const KEY_MS_CLIENT_SECRET = 'oauth.microsoft.client_secret';
    public const KEY_MS_TENANT = 'oauth.microsoft.tenant';
    public const KEY_GOOGLE_CLIENT_ID = 'oauth.google.client_id';
    public const KEY_GOOGLE_CLIENT_SECRET = 'oauth.google.client_secret';

    /** Secrets of these settings (BackupSecrets, settings form). */
    public const SECRET_KEYS = [self::KEY_MS_CLIENT_SECRET, self::KEY_GOOGLE_CLIENT_SECRET];

    /** `common` = work/school and personal Microsoft accounts. */
    public const DEFAULT_MS_TENANT = 'common';

    /** IMAP endpoint used when an OAuth account has no host of its own. */
    public const DEFAULT_IMAP_HOST = [self::MICROSOFT => 'outlook.office365.com', self::GOOGLE => 'imap.gmail.com'];

    public const LABELS = [self::MICROSOFT => 'Microsoft 365', self::GOOGLE => 'Google'];

    public function __construct(private ConfigService $config, private CryptoService $crypto)
    {
    }

    public function clientId(string $provider): string
    {
        return trim((string)$this->config->get($provider === self::GOOGLE ? self::KEY_GOOGLE_CLIENT_ID : self::KEY_MS_CLIENT_ID));
    }

    /** Decrypted client secret; '' when not set. Throws when it cannot be decrypted (APP_SECRET changed). */
    public function clientSecret(string $provider): string
    {
        $stored = (string)$this->config->get($provider === self::GOOGLE ? self::KEY_GOOGLE_CLIENT_SECRET : self::KEY_MS_CLIENT_SECRET);
        try {
            return (string)$this->crypto->decrypt($stored);
        } catch (\RuntimeException $e) {
            throw new OAuthException('Nie można odszyfrować sekretu klienta OAuth (' . self::LABELS[$provider] . ') - zmienił się APP_SECRET? Wpisz go ponownie w Ustawienia → Logowanie OAuth.');
        }
    }

    public function hasClientSecret(string $provider): bool
    {
        return (string)$this->config->get($provider === self::GOOGLE ? self::KEY_GOOGLE_CLIENT_SECRET : self::KEY_MS_CLIENT_SECRET) !== '';
    }

    /** Global Microsoft tenant: a GUID, a verified domain, `common` or `organizations`. */
    public function microsoftTenant(): string
    {
        $tenant = trim((string)$this->config->get(self::KEY_MS_TENANT));
        return $tenant !== '' ? $tenant : self::DEFAULT_MS_TENANT;
    }

    /** Both the client id and the secret are set (all flows use a confidential client). */
    public function isConfigured(string $provider): bool
    {
        return $this->clientId($provider) !== '' && $this->hasClientSecret($provider);
    }

    public static function isValidTenant(string $tenant): bool
    {
        return (bool)preg_match('/^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,98}[A-Za-z0-9])?)$/i', $tenant);
    }

    /** Client credentials need one directory, not a multi-tenant alias. */
    public static function isSpecificTenant(string $tenant): bool
    {
        return self::isValidTenant($tenant) && !in_array(strtolower($tenant), ['common', 'organizations', 'consumers'], true);
    }

    public function save(array $data): void
    {
        $this->config->set(self::KEY_MS_CLIENT_ID, trim((string)($data['microsoft_client_id'] ?? '')));
        $this->config->set(self::KEY_MS_TENANT, trim((string)($data['microsoft_tenant'] ?? '')));
        $this->config->set(self::KEY_GOOGLE_CLIENT_ID, trim((string)($data['google_client_id'] ?? '')));
        foreach ([self::KEY_MS_CLIENT_SECRET => 'microsoft', self::KEY_GOOGLE_CLIENT_SECRET => 'google'] as $key => $provider) {
            if (!empty($data[$provider . '_client_secret_clear'])) {
                $this->config->set($key, '');
            } elseif (trim((string)($data[$provider . '_client_secret'] ?? '')) !== '') {
                $this->config->set($key, $this->crypto->encrypt(trim((string)$data[$provider . '_client_secret'])));
            }
        }
    }

    /** @return string[] validation errors of the settings form */
    public static function validate(array $data): array
    {
        $errors = [];
        foreach (['microsoft_client_id' => 'Microsoft: identyfikator aplikacji', 'google_client_id' => 'Google: identyfikator klienta'] as $field => $label) {
            $v = trim((string)($data[$field] ?? ''));
            if ($v !== '' && !preg_match('/^[A-Za-z0-9._\-]{1,200}$/', $v)) {
                $errors[] = $label . ': nieprawidłowa wartość.';
            }
        }
        foreach (['microsoft_client_secret', 'google_client_secret'] as $field) {
            $v = (string)($data[$field] ?? '');
            if (strlen($v) > 500 || preg_match('/[\x00-\x1f\x7f]/', $v)) {
                $errors[] = 'Nieprawidłowy sekret klienta.';
            }
        }
        $tenant = trim((string)($data['microsoft_tenant'] ?? ''));
        if ($tenant !== '' && !self::isValidTenant($tenant)) {
            $errors[] = 'Microsoft: nieprawidłowy tenant (GUID, domena, common lub organizations).';
        }
        return $errors;
    }
}
