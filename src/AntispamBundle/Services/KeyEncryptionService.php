<?php

namespace AntispamBundle\Services;

class KeyEncryptionService
{
    private $secret;
    private $cipher = 'aes-256-cbc';

    public function __construct($secret)
    {
        $this->secret = $secret;
    }

    public function encrypt($plaintext)
    {
        if (empty($plaintext)) {
            return null;
        }

        $key = hash('sha256', $this->secret, true);
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));
        $encrypted = openssl_encrypt($plaintext, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);

        return base64_encode($iv . $encrypted);
    }

    public function decrypt($ciphertext)
    {
        if (empty($ciphertext)) {
            return null;
        }

        $key = hash('sha256', $this->secret, true);
        $data = base64_decode($ciphertext);
        $ivLength = openssl_cipher_iv_length($this->cipher);
        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);

        return openssl_decrypt($encrypted, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
    }
}
