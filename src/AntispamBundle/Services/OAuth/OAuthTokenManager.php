<?php

namespace AntispamBundle\Services\OAuth;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\CryptoService;
use Doctrine\Persistence\ManagerRegistry;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Access tokens of OAuth IMAP accounts: hands out a valid one, refreshing
 * it (refresh token, or client credentials for app-only) when it expires
 * within OAuthClient::EXPIRY_MARGIN.
 *
 * Refreshing is serialized per account with a file lock (var/data/locks):
 * the cron scan, a panel action and the digest may need a token at the
 * same time, and Microsoft rotates refresh tokens - two parallel refreshes
 * could store an already replaced one. After taking the lock the stored
 * tokens are read again, so the second process reuses the first one's token.
 *
 * Tokens are written with plain DBAL (like the scan cursor), so a refresh
 * during a scan never flushes or loses pending entity changes of the caller.
 * Failures are stored on the account (oauth_error, shown in the account list,
 * Stan systemu and antispam:doctor) and audited once per new error.
 */
class OAuthTokenManager
{
    public function __construct(
        private OAuthClient $client,
        private CryptoService $crypto,
        private ?ManagerRegistry $doctrine = null,
        private ?AuditLogger $audit = null,
        private ?LoggerInterface $logger = null,
        #[Autowire('%kernel.project_dir%/var/data/locks')] private ?string $lockDir = null,
    ) {
    }

    /** Valid access token for the account's XOAUTH2 login. */
    public function getAccessToken(Account $account): string
    {
        if (!$account->isOAuth()) {
            throw new OAuthException('Konto nie używa logowania OAuth.');
        }
        if (($token = $this->validStoredToken($account)) !== null) {
            return $token;
        }
        if (!$account->isOAuthAppOnly() && (string)$account->getOAuthRefreshToken() === '') {
            throw new OAuthException('Konto nie jest połączone z ' . OAuthSettings::LABELS[$account->getOAuthProvider()] . ' - użyj przycisku „Połącz” na stronie edycji konta.');
        }

        $lock = $this->lock($account);
        try {
            $this->reload($account);
            if (($token = $this->validStoredToken($account)) !== null) {
                return $token;
            }
            return $this->renew($account);
        } finally {
            if ($lock) {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }
    }

    /** Forces a new token (e.g. the stored one was refused by the IMAP server). */
    public function invalidate(Account $account): void
    {
        $account->setOAuthTokenExpiresAt(new \DateTime('-1 minute'));
        $this->write($account, ['oauth_token_expires_at' => (new \DateTime('-1 minute'))->format('Y-m-d H:i:s')]);
    }

    /** Stores the result of a finished consent (callback). The caller flushes the entity. */
    public function storeConsent(Account $account, array $tokens, ?string $address): void
    {
        $account->setOAuthAccessToken($this->crypto->encrypt((string)$tokens['access_token']));
        $account->setOAuthTokenExpiresAt(\DateTime::createFromImmutable(OAuthClient::expiresAt($tokens)));
        $account->setOAuthRefreshToken($this->crypto->encrypt((string)$tokens['refresh_token']));
        $account->setOAuthUsername($address);
        $account->setOAuthConnectedAt(new \DateTime());
        $account->setOAuthError(null);
    }

    private function renew(Account $account): string
    {
        $provider = (string)$account->getOAuthProvider();
        try {
            if ($account->isOAuthAppOnly()) {
                $tokens = $this->client->clientCredentials($account->getOAuthTenant());
            } else {
                try {
                    $refresh = (string)$this->crypto->decrypt($account->getOAuthRefreshToken());
                } catch (\RuntimeException $e) {
                    throw new OAuthException('Nie można odszyfrować tokenu odświeżania (zmienił się APP_SECRET?) - połącz konto ponownie.', 'invalid_grant');
                }
                $tokens = $this->client->refresh($provider, $refresh, $account->getOAuthTenant());
            }
        } catch (OAuthException $e) {
            $this->fail($account, $e);
            throw $e;
        }

        $expires = \DateTime::createFromImmutable(OAuthClient::expiresAt($tokens));
        $access = (string)$this->crypto->encrypt((string)$tokens['access_token']);
        $columns = [
            'oauth_access_token' => $access,
            'oauth_token_expires_at' => $expires->format('Y-m-d H:i:s'),
            'oauth_error' => null,
            'oauth_error_at' => null,
        ];
        $account->setOAuthAccessToken($access)->setOAuthTokenExpiresAt($expires)->setOAuthError(null);
        // Microsoft rotates refresh tokens; Google normally keeps the old one.
        if (!$account->isOAuthAppOnly() && is_string($tokens['refresh_token'] ?? null) && $tokens['refresh_token'] !== '') {
            $columns['oauth_refresh_token'] = $this->crypto->encrypt($tokens['refresh_token']);
            $account->setOAuthRefreshToken($columns['oauth_refresh_token']);
        }
        if ($account->isOAuthAppOnly() && $account->getOAuthConnectedAt() === null) {
            $account->setOAuthConnectedAt(new \DateTime());
            $columns['oauth_connected_at'] = (new \DateTime())->format('Y-m-d H:i:s');
        }
        $this->write($account, $columns);

        return (string)$tokens['access_token'];
    }

    private function fail(Account $account, OAuthException $e): void
    {
        $message = mb_substr($e->getMessage(), 0, 500);
        $changed = $account->getOAuthError() !== $message;
        $account->setOAuthError($message);
        $this->write($account, ['oauth_error' => $message, 'oauth_error_at' => (new \DateTime())->format('Y-m-d H:i:s')]);
        $this->logger?->warning('OAuth token refresh failed for account {id}: {error}', ['id' => $account->getId(), 'error' => $message]);
        if ($changed) {
            // Once per new error: the cron retries every few minutes.
            $this->audit?->log('account.oauth_refresh_failed', targetType: 'account', targetId: $account->getId(), label: $account->getName(), mailbox: $account->getEmail(), details: [
                'provider' => $account->getOAuthProvider(),
                'method' => $account->getImapAuthMethod(),
                'error_code' => $e->oauthError,
                'reconnect' => $e->needsReconnect(),
                'message' => $message,
            ]);
        }
    }

    private function validStoredToken(Account $account): ?string
    {
        $expires = $account->getOAuthTokenExpiresAt();
        if ((string)$account->getOAuthAccessToken() === '' || !$expires instanceof \DateTimeInterface
            || $expires->getTimestamp() - OAuthClient::EXPIRY_MARGIN <= time()) {
            return null;
        }
        try {
            $token = (string)$this->crypto->decrypt($account->getOAuthAccessToken());
        } catch (\RuntimeException) {
            return null;
        }
        return $token !== '' ? $token : null;
    }

    /** Tokens as stored now (another process may have refreshed them). */
    private function reload(Account $account): void
    {
        if (!$this->doctrine || $account->getId() === null) {
            return;
        }
        try {
            $row = $this->doctrine->getConnection()->fetchAssociative(
                'SELECT oauth_access_token, oauth_token_expires_at, oauth_refresh_token FROM antispam_account WHERE id = ?',
                [$account->getId()]
            );
        } catch (\Throwable) {
            return;
        }
        if (!$row) {
            return;
        }
        $account->setOAuthAccessToken($row['oauth_access_token']);
        $account->setOAuthTokenExpiresAt($row['oauth_token_expires_at'] ? new \DateTime($row['oauth_token_expires_at']) : null);
        if (!$account->isOAuthAppOnly() && (string)$row['oauth_refresh_token'] !== '') {
            $account->setOAuthRefreshToken($row['oauth_refresh_token']);
        }
    }

    private function write(Account $account, array $columns): void
    {
        if (!$this->doctrine || $account->getId() === null) {
            return;
        }
        try {
            $this->doctrine->getConnection()->update('antispam_account', $columns, ['id' => $account->getId()]);
        } catch (\Throwable $e) {
            $this->logger?->error('Cannot store OAuth tokens of account {id}: {error}', ['id' => $account->getId(), 'error' => $e->getMessage()]);
        }
    }

    /** @return resource|null */
    private function lock(Account $account)
    {
        if ($this->lockDir === null) {
            return null;
        }
        if (!is_dir($this->lockDir)) {
            @mkdir($this->lockDir, 0775, true);
        }
        $handle = @fopen($this->lockDir . '/oauth-' . sha1((string)$account->getId() . ':' . strtolower((string)$account->getEmail())) . '.lock', 'c');
        if ($handle === false) {
            return null;
        }
        // Blocking: a refresh takes a second; the token endpoint call has a 30 s cap.
        flock($handle, LOCK_EX);
        return $handle;
    }
}
