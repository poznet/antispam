<?php

namespace AntispamBundle\Services;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
/**
 * Signed, expiring action tokens for the quarantine digest links. Lets an
 * end user release / whitelist / delete one quarantined message without
 * logging in. The token is HMAC-SHA256 signed with the application secret.
 *
 * Format: base64url(json payload) "." base64url(hmac)
 */
class DigestTokenService
{
    const ACTION_RELEASE = 'release';
    const ACTION_WHITELIST = 'whitelist';
    const ACTION_DELETE = 'delete';

    private $secret;

    public function __construct(#[Autowire('%kernel.secret%')] string $secret)
    {
        if ((string)$secret === '') {
            throw new \InvalidArgumentException('DigestTokenService needs a non-empty secret');
        }
        $this->secret = (string)$secret;
    }

    /**
     * True when the secret is one of the placeholders shipped in this
     * repository - links signed with it could be forged by anyone.
     */
    public function usesDefaultSecret()
    {
        return in_array($this->secret, ['ThidsTokdenssNostSosSecretChadngedIt', 'ChangeMeInProductionPlease', 'ThisTokenIsNotSoSecretChangeIt'], true);
    }

    public static function actions()
    {
        return [self::ACTION_RELEASE, self::ACTION_WHITELIST, self::ACTION_DELETE];
    }

    /**
     * @param string $mailbox mailbox key ("imap" or "ssh-<accountId>")
     * @param string $id      message id inside that mailbox's quarantine
     * @param array  $meta    display-only data (sender, subject) shown on the confirmation page
     */
    public function create($mailbox, $id, $action, $ttlSeconds, array $meta = [])
    {
        if (!in_array($action, self::actions(), true)) {
            throw new \InvalidArgumentException('Unknown action: ' . $action);
        }
        $payload = [
            'm' => (string)$mailbox,
            'i' => (string)$id,
            'a' => $action,
            'e' => time() + (int)$ttlSeconds,
        ];
        if (!empty($meta['sender'])) {
            $payload['s'] = mb_substr((string)$meta['sender'], 0, 120, 'UTF-8');
        }
        if (!empty($meta['subject'])) {
            $payload['j'] = mb_substr((string)$meta['subject'], 0, 80, 'UTF-8');
        }
        $body = self::b64(json_encode($payload));
        return $body . '.' . self::b64($this->sign($body));
    }

    /**
     * @return array|null ['mailbox','id','action','expires','sender','subject'] or null when invalid / expired
     */
    public function verify($token)
    {
        $parts = explode('.', (string)$token);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return null;
        }
        $sig = self::unb64($parts[1]);
        if ($sig === false || !hash_equals($this->sign($parts[0]), $sig)) {
            return null;
        }
        $payload = json_decode((string)self::unb64($parts[0]), true);
        if (!is_array($payload) || !isset($payload['m'], $payload['i'], $payload['a'], $payload['e'])) {
            return null;
        }
        if ((int)$payload['e'] < time() || !in_array($payload['a'], self::actions(), true)) {
            return null;
        }
        return [
            'mailbox' => (string)$payload['m'],
            'id' => (string)$payload['i'],
            'action' => $payload['a'],
            'expires' => (int)$payload['e'],
            'sender' => isset($payload['s']) ? (string)$payload['s'] : '',
            'subject' => isset($payload['j']) ? (string)$payload['j'] : '',
        ];
    }

    private function sign($data)
    {
        return hash_hmac('sha256', 'quarantine-digest|' . $data, $this->secret, true);
    }

    private static function b64($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function unb64($data)
    {
        return base64_decode(strtr($data, '-_', '+/'), true);
    }
}
