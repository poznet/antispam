<?php

namespace AntispamBundle\Security\TwoFactor;

/**
 * RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s step) - what Google Authenticator,
 * Microsoft Authenticator, Aegis, 1Password... expect from an otpauth:// URI
 * without extra parameters. RFC 4648 base32 for the shared secret.
 *
 * Stateless and side-effect free; replay protection (a counter may be used
 * once) is the caller's job: verify() returns the matched counter.
 */
final class Totp
{
    public const DIGITS = 6;
    public const PERIOD = 30;
    /** Accepted clock drift, in steps on each side (±30 s). */
    public const WINDOW = 1;
    /** 160-bit secret, the RFC 4226 recommendation for HMAC-SHA1. */
    public const SECRET_BYTES = 20;

    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(self::SECRET_BYTES));
    }

    /** A syntactically usable secret (base32, at least 80 bits). */
    public static function isValidSecret(?string $secret): bool
    {
        $secret = self::normalizeSecret((string)$secret);
        return $secret !== '' && strlen($secret) >= 16 && preg_match('/^[A-Z2-7]+$/', $secret) === 1;
    }

    public static function normalizeSecret(string $secret): string
    {
        return strtoupper((string)preg_replace('/[\s=-]+/', '', $secret));
    }

    public static function counterAt(?int $time = null): int
    {
        return intdiv($time ?? time(), self::PERIOD);
    }

    public static function code(string $secret, int $counter): string
    {
        $key = self::base32Decode(self::normalizeSecret($secret));
        $hash = hash_hmac('sha1', pack('J', $counter), $key, true);
        $offset = ord($hash[19]) & 0x0f;
        $value = ((ord($hash[$offset]) & 0x7f) << 24)
            | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8)
            | ord($hash[$offset + 3]);

        return str_pad((string)($value % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Counter of the step the code belongs to (current ± WINDOW), or null.
     * Counters at or below $lastCounter are refused (each code works once).
     */
    public static function verify(string $secret, string $code, ?int $lastCounter = null, ?int $time = null): ?int
    {
        $code = (string)preg_replace('/\s+/', '', $code);
        if (!self::isValidSecret($secret) || preg_match('/^\d{' . self::DIGITS . '}$/', $code) !== 1) {
            return null;
        }
        $now = self::counterAt($time);
        $match = null;
        // Check every step of the window (constant work, no early exit).
        for ($c = $now - self::WINDOW; $c <= $now + self::WINDOW; $c++) {
            if (hash_equals(self::code($secret, $c), $code) && ($lastCounter === null || $c > $lastCounter)) {
                $match = $match ?? $c;
            }
        }
        return $match;
    }

    /** otpauth:// URI for the QR code (Key Uri Format). */
    public static function provisioningUri(string $secret, string $account, string $issuer): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        return 'otpauth://totp/' . $label . '?' . http_build_query([
            'secret' => self::normalizeSecret($secret),
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::DIGITS,
            'period' => self::PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public static function base32Encode(string $data): string
    {
        $bits = '';
        foreach (str_split($data) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }
        return $data === '' ? '' : $out;
    }

    public static function base32Decode(string $data): string
    {
        $data = self::normalizeSecret($data);
        $bits = '';
        foreach (str_split($data) as $char) {
            $pos = strpos(self::ALPHABET, $char);
            if ($pos === false) {
                throw new \InvalidArgumentException('Invalid base32 character');
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }
        return $data === '' ? '' : $out;
    }
}
