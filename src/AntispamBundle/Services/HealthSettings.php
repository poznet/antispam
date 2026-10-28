<?php

namespace AntispamBundle\Services;

use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Settings of the health checks and alerts ("Stan systemu" page), stored in
 * the key/value config table. The access token of /health?token= and
 * /metrics may also come from the HEALTH_TOKEN environment variable, which
 * then wins over the stored one.
 */
class HealthSettings
{
    const DEFAULT_FAIL_THRESHOLD = 2;
    const DEFAULT_SCAN_MAX_AGE = 60;
    const MIN_TOKEN_LENGTH = 16;

    public function __construct(
        private ConfigService $config,
        #[Autowire('%env(default::HEALTH_TOKEN)%')] private ?string $envToken = null,
    ) {
    }

    public function isAlertEnabled(): bool
    {
        $v = $this->config->get('health.alert_enabled');
        return $v === null ? true : self::bool($v);
    }

    /** Explicit recipients; empty = fall back to the digest sender address. @return string[] */
    public function getAlertEmails(): array
    {
        return self::parseEmails((string)$this->config->get('health.alert_email'));
    }

    /** @return string[] recipients of alert e-mails (explicit or the digest address) */
    public function getEffectiveAlertEmails(): array
    {
        $emails = $this->getAlertEmails();
        if (!$emails) {
            $emails = self::parseEmails((string)$this->config->get('digest.from_email'));
        }
        return $emails;
    }

    /** Sender of the alert e-mails: the digest sender, else the first recipient. */
    public function getFromEmail(): ?string
    {
        $from = self::parseEmails((string)$this->config->get('digest.from_email'));
        return $from[0] ?? ($this->getEffectiveAlertEmails()[0] ?? null);
    }

    public function getWebhookUrl(): string
    {
        $url = trim((string)$this->config->get('health.webhook_url'));
        return self::isValidWebhookUrl($url) ? $url : '';
    }

    /** Consecutive failing checks before an alert is sent. */
    public function getFailThreshold(): int
    {
        $v = (int)$this->config->get('health.fail_threshold');
        return $v >= 1 ? min($v, 100) : self::DEFAULT_FAIL_THRESHOLD;
    }

    /** Whether warnings ("degraded") alert too, not only failures. */
    public function isAlertOnWarn(): bool
    {
        return self::bool($this->config->get('health.alert_on_warn'));
    }

    /** Minutes after the last successful scan of an account before it is reported as failing. */
    public function getScanMaxAge(): int
    {
        $v = (int)$this->config->get('health.scan_max_age');
        return $v >= 5 ? min($v, 10080) : self::DEFAULT_SCAN_MAX_AGE;
    }

    /** Public base URL used in alert texts (the digest base URL). */
    public function getBaseUrl(): string
    {
        return rtrim(trim((string)$this->config->get('digest.base_url')), '/');
    }

    public function isTokenFromEnv(): bool
    {
        return trim((string)$this->envToken) !== '';
    }

    /** Token for the detailed /health and /metrics; '' = details disabled. */
    public function getToken(): string
    {
        $token = $this->isTokenFromEnv() ? trim((string)$this->envToken) : trim((string)$this->config->get('health.token'));
        return strlen($token) >= self::MIN_TOKEN_LENGTH ? $token : '';
    }

    public function isValidToken(?string $given): bool
    {
        $token = $this->getToken();
        return $token !== '' && $given !== null && $given !== '' && hash_equals($token, $given);
    }

    /**
     * Saves the form of the "Stan systemu" page.
     *
     * @return string[] validation errors (nothing is saved when not empty)
     */
    public function save(array $data): array
    {
        $errors = [];
        $emailsRaw = trim((string)($data['alert_email'] ?? ''));
        $emails = self::parseEmails($emailsRaw);
        if ($emailsRaw !== '' && count($emails) !== count(preg_split('/[\s,;]+/', $emailsRaw, -1, PREG_SPLIT_NO_EMPTY))) {
            $errors[] = 'Nieprawidłowy adres e-mail odbiorcy alertów.';
        }
        $webhook = trim((string)($data['webhook_url'] ?? ''));
        if ($webhook !== '' && !self::isValidWebhookUrl($webhook)) {
            $errors[] = 'Adres webhooka musi zaczynać się od https:// lub http://.';
        }
        $token = trim((string)($data['token'] ?? ''));
        if ($token !== '' && (strlen($token) < self::MIN_TOKEN_LENGTH || !preg_match('/^[A-Za-z0-9._~-]+$/', $token))) {
            $errors[] = sprintf('Token musi mieć co najmniej %d znaków (litery, cyfry, . _ ~ -).', self::MIN_TOKEN_LENGTH);
        }
        if ($errors) {
            return $errors;
        }

        $this->config->set('health.alert_enabled', !empty($data['alert_enabled']) ? '1' : '0');
        $this->config->set('health.alert_email', implode(', ', $emails));
        $this->config->set('health.webhook_url', $webhook);
        $this->config->set('health.fail_threshold', max(1, min(100, (int)($data['fail_threshold'] ?? self::DEFAULT_FAIL_THRESHOLD))));
        $this->config->set('health.alert_on_warn', !empty($data['alert_on_warn']) ? '1' : '0');
        $scanMaxAge = (int)($data['scan_max_age'] ?? 0);
        $this->config->set('health.scan_max_age', $scanMaxAge >= 5 ? min($scanMaxAge, 10080) : self::DEFAULT_SCAN_MAX_AGE);
        if (!$this->isTokenFromEnv()) {
            $this->config->set('health.token', $token);
        }
        return [];
    }

    /** @return string[] */
    public static function parseEmails(string $raw): array
    {
        $out = [];
        foreach (preg_split('/[\s,;]+/', $raw, -1, PREG_SPLIT_NO_EMPTY) as $email) {
            if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $out[] = $email;
            }
        }
        return array_values(array_unique($out));
    }

    public static function isValidWebhookUrl(string $url): bool
    {
        return (bool)preg_match('#^https?://[^\s/?\#]+#i', $url) && filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    private static function bool($v): bool
    {
        return $v === true || in_array(strtolower((string)$v), ['1', 'true', 'yes', 'on'], true);
    }
}
