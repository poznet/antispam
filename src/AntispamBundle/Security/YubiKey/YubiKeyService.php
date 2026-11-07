<?php

namespace AntispamBundle\Security\YubiKey;

use AntispamBundle\Entity\User;
use AntispamBundle\Entity\YubiKey;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use Doctrine\ORM\EntityManagerInterface;

/**
 * YubiKey (Yubico OTP) login of panel users.
 *
 * Settings (config table, Ustawienia → Użytkownicy → "Klucze YubiKey"):
 *   yubikey.client_id    - Client ID from https://upgrade.yubico.com/getapikey/
 *   yubikey.secret       - Secret Key (base64), stored encrypted (CryptoService)
 *   yubikey.api_url      - validation URL ('' = YubiCloud)
 *   yubikey.passwordless - '1' = the login page offers "Zaloguj kluczem YubiKey"
 *                          (touch the key, no password)
 *
 * Every database user can register keys under /my/2fa. A registered key is a
 * second factor after the password (like TOTP, TwoFactorService) and - when
 * passwordless is on - a login on its own (YubiKeyAuthenticator).
 * Without the API configured the keys are ignored (no lockout).
 */
class YubiKeyService
{
    public const CONFIG_CLIENT_ID = 'yubikey.client_id';
    public const CONFIG_SECRET = 'yubikey.secret';
    public const CONFIG_API_URL = 'yubikey.api_url';
    public const CONFIG_PASSWORDLESS = 'yubikey.passwordless';

    public const MAX_KEYS_PER_USER = 10;

    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
        private CryptoService $crypto,
        private YubicoOtpClient $client,
    ) {
    }

    /* ----- settings ------------------------------------------------------- */

    public function clientId(): string
    {
        return trim((string)$this->safeGet(self::CONFIG_CLIENT_ID));
    }

    public function hasSecret(): bool
    {
        return $this->secret() !== '';
    }

    public function apiUrl(): string
    {
        $url = trim((string)$this->safeGet(self::CONFIG_API_URL));
        return $url !== '' ? $url : YubicoOtpClient::DEFAULT_URL;
    }

    public function customApiUrl(): string
    {
        return trim((string)$this->safeGet(self::CONFIG_API_URL));
    }

    /** Client ID and Secret Key are set - the keys can be validated. */
    public function isConfigured(): bool
    {
        return preg_match('/^\d+$/', $this->clientId()) === 1 && $this->hasSecret();
    }

    public function isPasswordlessEnabled(): bool
    {
        return $this->isConfigured() && (string)$this->safeGet(self::CONFIG_PASSWORDLESS) === '1';
    }

    /**
     * Save the API settings. $secret null = keep the stored one, '' = clear.
     *
     * @return string[] validation errors (nothing saved when not empty)
     */
    public function saveSettings(string $clientId, ?string $secret, string $apiUrl, bool $passwordless): array
    {
        $clientId = trim($clientId);
        $apiUrl = trim($apiUrl);
        $errors = [];
        if ($clientId !== '' && preg_match('/^\d{1,12}$/', $clientId) !== 1) {
            $errors[] = 'Client ID to liczba z upgrade.yubico.com/getapikey.';
        }
        if ($secret !== null && $secret !== '') {
            $secret = trim($secret);
            $raw = base64_decode($secret, true);
            if ($raw === false || strlen($raw) < 16) {
                $errors[] = 'Secret Key musi być kluczem base64 z upgrade.yubico.com/getapikey.';
            }
        }
        if ($apiUrl !== '' && (!filter_var($apiUrl, FILTER_VALIDATE_URL) || !preg_match('#^https://#i', $apiUrl))) {
            $errors[] = 'Adres serwera weryfikacji musi zaczynać się od https://.';
        }
        if ($errors) {
            return $errors;
        }
        $this->config->set(self::CONFIG_CLIENT_ID, $clientId);
        if ($secret !== null) {
            $this->config->set(self::CONFIG_SECRET, $secret === '' ? '' : $this->crypto->encrypt($secret));
        }
        $this->config->set(self::CONFIG_API_URL, $apiUrl);
        $this->config->set(self::CONFIG_PASSWORDLESS, $passwordless ? '1' : '0');
        return [];
    }

    /** Validate an OTP against the configured server: STATUS_OK or a failure status. */
    public function check(string $otp): string
    {
        if (!$this->isConfigured()) {
            return YubicoOtpClient::STATUS_NO_SUCH_CLIENT;
        }
        return $this->client->verify($otp, $this->clientId(), $this->secret(), $this->apiUrl());
    }

    /* ----- keys ------------------------------------------------------------ */

    /** @return YubiKey[] */
    public function keysOf(User $user): array
    {
        return $this->repo()->findByUser($user);
    }

    /** The user has keys and they can be validated (counts as 2FA on). */
    public function isActiveFor(?object $user): bool
    {
        return $user instanceof User && $this->isConfigured() && $this->keysOf($user) !== [];
    }

    /**
     * Register the key that typed $otp. The OTP is validated first (proves the
     * key is real and present).
     *
     * @return YubiKey|string the new key or a Polish error message
     */
    public function register(User $user, string $otp, string $name): YubiKey|string
    {
        $otp = YubicoOtpClient::normalize($otp);
        $name = trim($name);
        if (!$this->isConfigured()) {
            return 'Logowanie kluczem YubiKey nie jest skonfigurowane (administrator: Ustawienia → Użytkownicy).';
        }
        if (!YubicoOtpClient::isOtp($otp)) {
            return 'To nie jest kod z klucza YubiKey - kliknij w pole i dotknij klucza.';
        }
        if (count($this->keysOf($user)) >= self::MAX_KEYS_PER_USER) {
            return sprintf('Można zarejestrować najwyżej %d kluczy.', self::MAX_KEYS_PER_USER);
        }
        $publicId = YubicoOtpClient::publicId($otp);
        if ($this->repo()->findOneByPublicId($publicId)) {
            return 'Ten klucz jest już zarejestrowany.';
        }
        $status = $this->check($otp);
        if ($status !== YubicoOtpClient::STATUS_OK) {
            return YubicoOtpClient::describe($status);
        }
        $key = new YubiKey($user, $publicId, $name !== '' ? mb_substr($name, 0, 100) : 'YubiKey ' . $publicId);
        $key->markUsed();
        $this->em->persist($key);
        $this->em->flush();
        return $key;
    }

    public function remove(User $user, int $keyId): ?YubiKey
    {
        $key = $this->repo()->find($keyId);
        if (!$key instanceof YubiKey || $key->getUser()->getId() !== $user->getId()) {
            return null;
        }
        $this->em->remove($key);
        $this->em->flush();
        return $key;
    }

    /** Admin reset: drop all keys of the user. */
    public function removeAll(User $user): int
    {
        return $this->repo()->deleteByUser($user);
    }

    /** @return array<int, int> user id => number of keys */
    public function keyCounts(): array
    {
        return $this->repo()->countByUser();
    }

    /* ----- login ----------------------------------------------------------- */

    /**
     * Second factor: the OTP comes from one of the user's keys and is valid.
     * Returns STATUS_OK, or a failure status ('UNKNOWN_KEY' for a foreign key).
     */
    public function verifyForUser(User $user, string $otp): string
    {
        if (!YubicoOtpClient::isOtp($otp)) {
            return YubicoOtpClient::STATUS_BAD_OTP;
        }
        $key = $this->repo()->findOneByPublicId(YubicoOtpClient::publicId($otp));
        if (!$key || $key->getUser()->getId() !== $user->getId()) {
            return 'UNKNOWN_KEY';
        }
        $status = $this->check($otp);
        if ($status === YubicoOtpClient::STATUS_OK) {
            $key->markUsed();
            $this->em->flush();
        }
        return $status;
    }

    /** Key that typed the OTP (by public ID), if registered. */
    public function findKeyForOtp(string $otp): ?YubiKey
    {
        $publicId = YubicoOtpClient::publicId($otp);
        return $publicId === '' ? null : $this->repo()->findOneByPublicId($publicId);
    }

    public function markUsed(YubiKey $key): void
    {
        $key->markUsed();
        $this->em->flush();
    }

    private function secret(): string
    {
        $stored = (string)$this->safeGet(self::CONFIG_SECRET);
        if ($stored === '') {
            return '';
        }
        try {
            return (string)$this->crypto->decrypt($stored);
        } catch (\Throwable $e) {
            // APP_SECRET changed: unreadable - behave as not configured.
            return '';
        }
    }

    /** The env admin must log in without the database: a missing table = not configured. */
    private function safeGet(string $key): mixed
    {
        try {
            return $this->config->get($key);
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function repo(): \AntispamBundle\Repository\YubiKeyRepository
    {
        return $this->em->getRepository(YubiKey::class);
    }
}
