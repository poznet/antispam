<?php

namespace AntispamBundle\Services;

/**
 * Symmetric encryption for secrets at rest (e.g. account IMAP passwords).
 * Uses libsodium secretbox; key is derived from %secret% so we don't need
 * to manage a separate keyring. Output is prefixed with "enc:v1:" so we
 * can distinguish legacy plaintext values still present in the database.
 */
class CryptoService
{
    const PREFIX = 'enc:v1:';

    private $key;

    public function __construct($appSecret)
    {
        if (!function_exists('sodium_crypto_secretbox')) {
            throw new \RuntimeException('libsodium is required for secret encryption');
        }
        $this->key = hash('sha256', 'antispam-account-secret:' . (string)$appSecret, true);
    }

    public function isEncrypted($value)
    {
        return is_string($value) && strncmp($value, self::PREFIX, strlen(self::PREFIX)) === 0;
    }

    public function encrypt($plaintext)
    {
        if ($plaintext === null || $plaintext === '') {
            return $plaintext;
        }
        if ($this->isEncrypted($plaintext)) {
            return $plaintext;
        }
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = sodium_crypto_secretbox((string)$plaintext, $nonce, $this->key);
        return self::PREFIX . base64_encode($nonce . $cipher);
    }

    public function decrypt($value)
    {
        if ($value === null || $value === '') {
            return $value;
        }
        if (!$this->isEncrypted($value)) {
            // Legacy plaintext row — return as-is so existing data keeps working.
            return $value;
        }
        $raw = base64_decode(substr($value, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new \RuntimeException('Invalid encrypted payload');
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $cipher = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open($cipher, $nonce, $this->key);
        if ($plain === false) {
            throw new \RuntimeException('Failed to decrypt secret');
        }
        return $plain;
    }
}
