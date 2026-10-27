<?php

namespace AntispamBundle\Services;

use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Encrypts secrets stored in the database (account IMAP passwords) with
 * libsodium secretbox. The key is derived from APP_SECRET, so changing
 * APP_SECRET makes stored passwords unreadable (they have to be re-entered).
 *
 * Encrypted values start with "enc:v1:". Anything else is a legacy plaintext
 * value and is returned as-is, so existing rows keep working until they are
 * saved again.
 */
class CryptoService
{
    public const PREFIX = 'enc:v1:';

    private string $key;

    public function __construct(#[Autowire('%env(APP_SECRET)%')] string $appSecret)
    {
        $this->key = hash('sha256', 'antispam-account-secret:' . $appSecret, true);
    }

    public function isEncrypted($value): bool
    {
        return is_string($value) && strncmp($value, self::PREFIX, strlen(self::PREFIX)) === 0;
    }

    public function encrypt(?string $plaintext): ?string
    {
        if ($plaintext === null || $plaintext === '' || $this->isEncrypted($plaintext)) {
            return $plaintext;
        }
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return self::PREFIX . base64_encode($nonce . sodium_crypto_secretbox($plaintext, $nonce, $this->key));
    }

    public function decrypt(?string $value): ?string
    {
        if ($value === null || $value === '' || !$this->isEncrypted($value)) {
            return $value;
        }
        $raw = base64_decode(substr($value, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new \RuntimeException('Invalid encrypted secret');
        }
        $plain = sodium_crypto_secretbox_open(
            substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $this->key
        );
        if ($plain === false) {
            throw new \RuntimeException('Cannot decrypt the stored password (was APP_SECRET changed?) - enter it again');
        }

        return $plain;
    }
}
