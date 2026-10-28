<?php

namespace AntispamBundle\Services\OAuth;

/**
 * OAuth2 failure (provider not configured, token endpoint error, invalid
 * callback). The message is shown in the panel and stored as the account's
 * token error - it never contains a token or the client secret.
 */
class OAuthException extends \RuntimeException
{
    /**
     * @param string|null $oauthError OAuth error code from the provider (invalid_grant, invalid_client...)
     */
    public function __construct(string $message, public readonly ?string $oauthError = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    /** The refresh token is dead (revoked, expired, password changed): only a new consent helps. */
    public function needsReconnect(): bool
    {
        return in_array($this->oauthError, ['invalid_grant', 'interaction_required', 'consent_required', 'login_required'], true);
    }
}
