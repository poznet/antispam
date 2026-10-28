<?php

namespace AntispamBundle\Security\TwoFactor;

use AntispamBundle\Entity\User;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Two-factor authentication (TOTP) of panel logins.
 *
 * - Database users (Entity\User) keep an encrypted secret, the last used time
 *   step and hashed backup codes in antispam_user.
 * - The legacy environment admin (ADMIN_USER, an InMemoryUser) has nothing in
 *   the database: its secret comes from ADMIN_TOTP_SECRET (base32), it has no
 *   backup codes (recovery = change the variable) and its replay counter is
 *   kept in the config table.
 * - A login counts as "second factor done" through a session marker bound to
 *   the user identifier; it is cleared on every new login (TwoFactorGuard),
 *   so the check fails closed: no marker = code required.
 * - Every code check (login, enable, disable, new backup codes) goes through
 *   the `two_factor_code` rate limiter (per login, see framework.yaml).
 */
class TwoFactorService
{
    public const ISSUER = 'Antispam Pancernapanda';
    public const SESSION_PASSED = '_antispam_2fa_passed';
    public const SESSION_PENDING_SECRET = '_antispam_2fa_setup_secret';
    /** Config key: '1' = administrators must use 2FA. */
    public const CONFIG_REQUIRED_ADMINS = 'security.2fa_required_admins';
    /** Config key: replay counter of the env admin. */
    public const CONFIG_ENV_COUNTER = 'security.2fa_env_admin_counter';

    public const BACKUP_CODE_COUNT = 10;
    private const BACKUP_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
    private const BACKUP_LENGTH = 10;
    /** bcrypt cost of the backup code hashes (lowered by the test suite only). */
    public static int $backupHashCost = 10;

    public const METHOD_TOTP = 'totp';
    public const METHOD_BACKUP = 'backup';

    private string $envSecret;

    public function __construct(
        private EntityManagerInterface $em,
        private CryptoService $crypto,
        private ConfigService $config,
        #[Autowire(service: 'limiter.two_factor_code')] private RateLimiterFactoryInterface $limiter,
        #[Autowire('%env(default::ADMIN_TOTP_SECRET)%')] ?string $envSecret = '',
    ) {
        $this->envSecret = Totp::normalizeSecret((string)$envSecret);
    }

    public function isEnvAdmin(?UserInterface $user): bool
    {
        return $user instanceof InMemoryUser;
    }

    /** ADMIN_TOTP_SECRET is set to a usable value. */
    public function hasEnvSecret(): bool
    {
        return Totp::isValidSecret($this->envSecret);
    }

    public function isEnabled(?UserInterface $user): bool
    {
        if ($user instanceof User) {
            return $user->isTotpEnabled();
        }
        return $this->isEnvAdmin($user) && $this->hasEnvSecret();
    }

    public function isRequiredForAdmins(): bool
    {
        return (string)$this->config->get(self::CONFIG_REQUIRED_ADMINS) === '1';
    }

    public function setRequiredForAdmins(bool $required): void
    {
        $this->config->set(self::CONFIG_REQUIRED_ADMINS, $required ? '1' : '0');
    }

    /**
     * The user must set up 2FA before using the panel: enforcement is on, the
     * user is a database administrator and has no 2FA yet. The env admin
     * cannot enrol in the panel (ADMIN_TOTP_SECRET), so it is never forced
     * into a setup it could not finish - see docs/users.md.
     */
    public function needsSetup(?UserInterface $user): bool
    {
        return $user instanceof User && $user->isAdmin() && !$user->isTotpEnabled() && $this->isRequiredForAdmins();
    }

    /* ----- session marker ------------------------------------------------ */

    public function isPassed(SessionInterface $session, UserInterface $user): bool
    {
        $marker = $session->get(self::SESSION_PASSED);
        return is_string($marker) && hash_equals(self::marker($user), $marker);
    }

    public function markPassed(SessionInterface $session, UserInterface $user): void
    {
        $session->set(self::SESSION_PASSED, self::marker($user));
    }

    public function clearPassed(SessionInterface $session): void
    {
        $session->remove(self::SESSION_PASSED);
    }

    private static function marker(UserInterface $user): string
    {
        return hash('sha256', get_class($user) . "\0" . $user->getUserIdentifier());
    }

    /* ----- rate limit ------------------------------------------------------ */

    /** Consume one attempt; false = too many attempts for this login. */
    public function consumeAttempt(UserInterface $user): bool
    {
        return $this->limiter->create(self::limiterKey($user))->consume(1)->isAccepted();
    }

    /** A successful code resets the counter (like login_throttling does). */
    public function resetAttempts(UserInterface $user): void
    {
        $this->limiter->create(self::limiterKey($user))->reset();
    }

    private static function limiterKey(UserInterface $user): string
    {
        return '2fa-' . strtolower($user->getUserIdentifier());
    }

    /* ----- verification ---------------------------------------------------- */

    /**
     * Check a code typed by the user: a TOTP code (each one usable once) or,
     * for database users, an unused backup code (consumed). Persists the new
     * replay counter / remaining backup codes. Does not rate limit - callers
     * call consumeAttempt() first.
     *
     * @return string|null METHOD_TOTP | METHOD_BACKUP, or null when wrong
     */
    public function verify(UserInterface $user, string $code): ?string
    {
        $code = trim($code);
        if ($code === '') {
            return null;
        }
        if ($user instanceof User) {
            if (!$user->isTotpEnabled()) {
                return null;
            }
            $counter = Totp::verify($this->secretOf($user), $code, $user->getTotpLastCounter());
            if ($counter !== null) {
                $user->setTotpLastCounter($counter);
                $this->em->flush();
                return self::METHOD_TOTP;
            }
            if ($this->consumeBackupCode($user, $code)) {
                $this->em->flush();
                return self::METHOD_BACKUP;
            }
            return null;
        }
        if ($this->isEnvAdmin($user) && $this->hasEnvSecret()) {
            // The env admin must work without the database (AdminUserProvider):
            // with the config table unreachable only replay protection is lost.
            try {
                $last = $this->config->get(self::CONFIG_ENV_COUNTER);
            } catch (\Throwable $e) {
                $last = null;
            }
            $counter = Totp::verify($this->envSecret, $code, is_numeric($last) ? (int)$last : null);
            if ($counter !== null) {
                try {
                    $this->config->set(self::CONFIG_ENV_COUNTER, (string)$counter);
                } catch (\Throwable $e) {
                }
                return self::METHOD_TOTP;
            }
        }
        return null;
    }

    /** Verify a code against a secret that is not stored yet (setup confirmation). */
    public function verifyPendingSecret(string $secret, string $code): ?int
    {
        return Totp::verify($secret, $code);
    }

    /* ----- enrolment ------------------------------------------------------- */

    /** Secret being set up in this session (created on first call). */
    public function pendingSecret(SessionInterface $session): string
    {
        $secret = $session->get(self::SESSION_PENDING_SECRET);
        if (!is_string($secret) || !Totp::isValidSecret($secret)) {
            $secret = Totp::generateSecret();
            $session->set(self::SESSION_PENDING_SECRET, $secret);
        }
        return $secret;
    }

    public function discardPendingSecret(SessionInterface $session): void
    {
        $session->remove(self::SESSION_PENDING_SECRET);
    }

    /**
     * Turn 2FA on with a confirmed secret.
     *
     * @return string[] the backup codes in plain text - shown once, only hashes are kept
     */
    public function enable(User $user, string $secret, int $confirmedCounter): array
    {
        $user->setTotpSecret($this->crypto->encrypt(Totp::normalizeSecret($secret)))
            ->setTotpEnabledAt(new \DateTime())
            ->setTotpLastCounter($confirmedCounter);
        $codes = $this->replaceBackupCodes($user);
        $this->em->flush();
        return $codes;
    }

    public function disable(User $user): void
    {
        $user->clearTotp();
        $this->em->flush();
    }

    /** @return string[] new backup codes (plain text); the old ones stop working */
    public function regenerateBackupCodes(User $user): array
    {
        $codes = $this->replaceBackupCodes($user);
        $this->em->flush();
        return $codes;
    }

    public function remainingBackupCodes(?UserInterface $user): int
    {
        return $user instanceof User ? count($user->getTotpBackupCodes()) : 0;
    }

    /** otpauth:// URI of a secret for this user. */
    public function provisioningUri(UserInterface $user, string $secret): string
    {
        return Totp::provisioningUri($secret, $user->getUserIdentifier(), self::ISSUER);
    }

    /** @return string[] */
    private function replaceBackupCodes(User $user): array
    {
        $codes = [];
        $hashes = [];
        for ($i = 0; $i < self::BACKUP_CODE_COUNT; $i++) {
            $code = '';
            for ($j = 0; $j < self::BACKUP_LENGTH; $j++) {
                $code .= self::BACKUP_ALPHABET[random_int(0, strlen(self::BACKUP_ALPHABET) - 1)];
            }
            $codes[] = substr($code, 0, 5) . '-' . substr($code, 5);
            $hashes[] = password_hash($code, PASSWORD_BCRYPT, ['cost' => self::$backupHashCost]);
        }
        $user->setTotpBackupCodes($hashes);
        return $codes;
    }

    private function consumeBackupCode(User $user, string $code): bool
    {
        $normalized = strtolower((string)preg_replace('/[\s-]+/', '', $code));
        if (strlen($normalized) !== self::BACKUP_LENGTH || preg_match('/^[a-z0-9]+$/', $normalized) !== 1) {
            return false;
        }
        $hashes = $user->getTotpBackupCodes();
        foreach ($hashes as $i => $hash) {
            if (is_string($hash) && password_verify($normalized, $hash)) {
                unset($hashes[$i]);
                $user->setTotpBackupCodes(array_values($hashes));
                return true;
            }
        }
        return false;
    }

    private function secretOf(User $user): string
    {
        try {
            return (string)$this->crypto->decrypt($user->getTotpSecret());
        } catch (\Throwable $e) {
            // APP_SECRET changed: the secret is unreadable, no TOTP code can match
            // (backup codes still work, an admin can reset 2FA).
            return '';
        }
    }
}
