<?php

namespace AntispamBundle\Services\Backup;

/** Which `config` keys a backup treats as secrets or as runtime state. */
final class BackupSecrets
{
    /**
     * `config` keys holding a secret: exported only with --include-secrets and
     * then encrypted with the instance key. The legacy mailbox password is
     * stored encrypted, the API keys in plain text (as the settings forms do).
     */
    public const CONFIG_KEYS = [
        'password',
        'scoring.vt_api_key',
        'url.gsb_api_key',
        'feed.server_key',
        'feed.remote_key',
        'oauth.microsoft.client_secret',
        'oauth.google.client_secret',
    ];

    /** Secrets kept encrypted (CryptoService) in the database, also after an import. */
    public const STORED_ENCRYPTED = ['password', 'oauth.microsoft.client_secret', 'oauth.google.client_secret'];

    /**
     * Runtime state, not configuration (sync markers, cursors, last-sent
     * markers): never exported, never touched by an import - also not in
     * replace mode.
     */
    public const STATE_PREFIXES = [
        'cert.last_',
        'feed.last_',
        'digest.last_sent.',
        'imap.legacy_cursor',
    ];

    private function __construct()
    {
    }

    public static function isSecret(string $key): bool
    {
        return in_array($key, self::CONFIG_KEYS, true);
    }

    public static function isState(string $key): bool
    {
        foreach (self::STATE_PREFIXES as $prefix) {
            if (strncmp($key, $prefix, strlen($prefix)) === 0) {
                return true;
            }
        }

        return false;
    }
}
