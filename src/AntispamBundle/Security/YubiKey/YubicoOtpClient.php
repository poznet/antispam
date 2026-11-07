<?php

namespace AntispamBundle\Security\YubiKey;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Yubico OTP validation protocol 2.0 client (YubiCloud api.yubico.com or a
 * self-hosted yubikey-val server).
 *
 * https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html
 *
 * - the request carries the Client ID, the OTP and a random nonce, signed
 *   with HMAC-SHA1 of the base64-decoded Secret Key (parameter h);
 * - the answer is accepted only when its own signature is valid, it echoes
 *   the same otp and nonce and status=OK. The server keeps the usage counter
 *   of every key, so an OTP can be validated once (REPLAYED_OTP afterwards).
 *
 * Stateless; credentials are passed per call by YubiKeyService.
 */
class YubicoOtpClient
{
    public const DEFAULT_URL = 'https://api.yubico.com/wsapi/2.0/verify';

    /** Statuses of the protocol (plus our own transport/verification errors). */
    public const STATUS_OK = 'OK';
    public const STATUS_BAD_OTP = 'BAD_OTP';
    public const STATUS_REPLAYED_OTP = 'REPLAYED_OTP';
    public const STATUS_BAD_SIGNATURE = 'BAD_SIGNATURE';
    public const STATUS_NO_SUCH_CLIENT = 'NO_SUCH_CLIENT';
    /** Local: the server could not be reached / answered garbage. */
    public const STATUS_BACKEND_ERROR = 'BACKEND_ERROR';
    /** Local: the answer was not signed with our secret or did not echo our otp/nonce. */
    public const STATUS_BAD_RESPONSE = 'BAD_RESPONSE_SIGNATURE';

    /** Modhex alphabet the key "types" in. */
    private const MODHEX = 'cbdefghijklnrtuv';
    /** Public ID (0-16 modhex) + 32 modhex chars of the encrypted token. */
    private const OTP_PATTERN = '/^[cbdefghijklnrtuv]{32,48}$/';

    public function __construct(
        private HttpClientInterface $http,
        private ?LoggerInterface $logger = null,
    ) {
        $this->logger ??= new NullLogger();
    }

    /** Trim + lowercase what the key typed (some layouts add Shift). */
    public static function normalize(string $otp): string
    {
        return strtolower(trim($otp));
    }

    /** Syntactically a Yubico OTP: 32 chars of encrypted token after a 0-16 char public ID. */
    public static function isOtp(string $otp): bool
    {
        $otp = self::normalize($otp);
        return preg_match(self::OTP_PATTERN, $otp) === 1 && strlen($otp) > 32;
    }

    /** Public ID of the key that typed the OTP (all but the last 32 chars). */
    public static function publicId(string $otp): string
    {
        $otp = self::normalize($otp);
        return self::isOtp($otp) ? substr($otp, 0, -32) : '';
    }

    public static function isValidPublicId(string $id): bool
    {
        return preg_match('/^[' . self::MODHEX . ']{2,16}$/', $id) === 1;
    }

    /**
     * Validate an OTP. Returns STATUS_OK or the failure status; never throws.
     *
     * @param string $secret base64 Secret Key from upgrade.yubico.com/getapikey ('' = unsigned request, not recommended)
     */
    public function verify(string $otp, string $clientId, string $secret, string $url = self::DEFAULT_URL): string
    {
        $otp = self::normalize($otp);
        if (!self::isOtp($otp)) {
            return self::STATUS_BAD_OTP;
        }
        $key = $secret !== '' ? base64_decode($secret, true) : '';
        if ($key === false) {
            $this->logger->error('YubiKey: Secret Key is not valid base64');
            return self::STATUS_BAD_SIGNATURE;
        }

        $nonce = bin2hex(random_bytes(16));
        $params = ['id' => $clientId, 'nonce' => $nonce, 'otp' => $otp];
        if ($key !== '') {
            $params['h'] = self::sign($params, $key);
        }

        try {
            $response = $this->http->request('GET', $url !== '' ? $url : self::DEFAULT_URL, [
                'query' => $params,
                'timeout' => 10,
                'max_duration' => 15,
                'headers' => ['User-Agent' => 'Antispam-Pancernapanda'],
            ]);
            $body = $response->getContent(false);
            $code = $response->getStatusCode();
        } catch (\Throwable $e) {
            $this->logger->error('YubiKey: validation server unreachable: {error}', ['error' => $e->getMessage(), 'url' => $url]);
            return self::STATUS_BACKEND_ERROR;
        }
        if ($code !== 200) {
            $this->logger->error('YubiKey: validation server answered HTTP {code}', ['code' => $code, 'url' => $url]);
            return self::STATUS_BACKEND_ERROR;
        }

        $answer = self::parse($body);
        $status = $answer['status'] ?? '';
        if ($status === '') {
            $this->logger->error('YubiKey: unparsable answer from the validation server', ['url' => $url]);
            return self::STATUS_BACKEND_ERROR;
        }
        // Error statuses (BAD_SIGNATURE, NO_SUCH_CLIENT...) may come unsigned or
        // signed with an unknown key; they are failures either way.
        if ($key !== '') {
            $h = $answer['h'] ?? '';
            unset($answer['h']);
            if ($h === '' || !hash_equals(self::sign($answer, $key), $h)) {
                if ($status === self::STATUS_OK) {
                    $this->logger->error('YubiKey: answer signature mismatch (wrong Secret Key or tampered answer)', ['url' => $url]);
                    return self::STATUS_BAD_RESPONSE;
                }
                $this->logger->warning('YubiKey: validation failed: {status}', ['status' => $status]);
                return $status;
            }
        }
        if ($status !== self::STATUS_OK) {
            $this->logger->info('YubiKey: OTP rejected: {status}', ['status' => $status, 'public_id' => self::publicId($otp)]);
            return $status;
        }
        if (!hash_equals($otp, (string)($answer['otp'] ?? '')) || !hash_equals($nonce, (string)($answer['nonce'] ?? ''))) {
            $this->logger->error('YubiKey: answer does not echo our otp / nonce', ['url' => $url]);
            return self::STATUS_BAD_RESPONSE;
        }
        return self::STATUS_OK;
    }

    /** base64(HMAC-SHA1(k1=v1&k2=v2..., key)) over the pairs sorted by key. */
    public static function sign(array $params, string $key): string
    {
        ksort($params, SORT_STRING);
        $pairs = [];
        foreach ($params as $k => $v) {
            $pairs[] = $k . '=' . $v;
        }
        return base64_encode(hash_hmac('sha1', implode('&', $pairs), $key, true));
    }

    /** "key=value" lines of the answer (values may contain '=' - base64). */
    public static function parse(string $body): array
    {
        $out = [];
        foreach (preg_split('/\r?\n/', $body) as $line) {
            $line = trim($line);
            if ($line === '' || !str_contains($line, '=')) {
                continue;
            }
            [$k, $v] = explode('=', $line, 2);
            $out[trim($k)] = trim($v);
        }
        return $out;
    }

    /** Polish message of a failure status, for flashes. */
    public static function describe(string $status): string
    {
        return match ($status) {
            self::STATUS_OK => 'OK',
            self::STATUS_BAD_OTP => 'Nieprawidłowy kod z klucza YubiKey.',
            self::STATUS_REPLAYED_OTP => 'Ten kod z klucza YubiKey został już użyty - dotknij klucza ponownie.',
            self::STATUS_NO_SUCH_CLIENT, self::STATUS_BAD_SIGNATURE, self::STATUS_BAD_RESPONSE => 'Serwer Yubico odrzucił dane API (Client ID / Secret Key) - sprawdź konfigurację YubiKey.',
            self::STATUS_BACKEND_ERROR => 'Serwer weryfikacji Yubico jest nieosiągalny - spróbuj za chwilę.',
            default => 'Klucz YubiKey nie został zweryfikowany (' . $status . ').',
        };
    }
}
