<?php

namespace AntispamBundle\Services;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;

/**
 * Turns health reports into alerts (e-mail and/or a JSON webhook), without
 * repeating them:
 *
 *   - a check counts as failing when its status is "fail" (or "warn" with
 *     "alert on warnings" enabled);
 *   - it is reported once, after failing N consecutive runs (threshold);
 *   - once it passes again a single recovery message follows;
 *   - one notification per run aggregates every new problem and recovery.
 *
 * State lives in the config table (health.alert_state). When every
 * configured channel fails, nothing is marked as sent, so the next run
 * retries. Checks missing from a report keep their state while the database
 * check fails (the other checks were not run); otherwise they are dropped
 * silently (deleted account, check that no longer exists).
 */
class HealthAlerter
{
    const STATE_KEY = 'health.alert_state';
    const WEBHOOK_TIMEOUT = 10;

    public function __construct(
        private ConfigService $config,
        private HealthSettings $settings,
        private MailerInterface $mailer,
        private ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /** @return array{checks: array, last_run_at?: string, last_status?: string, last_notification_at?: string, last_errors?: string[]} */
    public function getState(): array
    {
        $state = $this->config->get(self::STATE_KEY);
        if (!is_array($state)) {
            $state = [];
        }
        $state['checks'] = is_array($state['checks'] ?? null) ? $state['checks'] : [];
        return $state;
    }

    /**
     * Updates the failure counters with $report and sends what is due.
     *
     * @return array{problems: array, recovered: array, sent: string[], errors: string[]}
     */
    public function process(array $report): array
    {
        $state = $this->getState();
        $threshold = $this->settings->getFailThreshold();
        $alertOnWarn = $this->settings->isAlertOnWarn();
        $enabled = $this->settings->isAlertEnabled();
        $now = (string)($report['checked_at'] ?? date(DATE_ATOM));

        $dbDown = false;
        $seen = [];
        $problems = [];
        $recovered = [];
        foreach ($report['checks'] as $check) {
            $key = $check['key'];
            $seen[$key] = true;
            if ($key === 'db' && $check['status'] === HealthService::FAIL) {
                $dbDown = true;
            }
            $failing = $check['status'] === HealthService::FAIL || ($alertOnWarn && $check['status'] === HealthService::WARN);
            $entry = $state['checks'][$key] ?? null;

            if ($failing) {
                $entry = [
                    'fails' => (int)($entry['fails'] ?? 0) + 1,
                    'alerted' => !empty($entry['alerted']),
                    'since' => $entry['since'] ?? $now,
                    'label' => $check['label'],
                    'status' => $check['status'],
                    'message' => $check['message'],
                ];
                if (!$entry['alerted'] && $entry['fails'] >= $threshold && $enabled) {
                    $problems[$key] = $check + ['since' => $entry['since'], 'fails' => $entry['fails']];
                }
                $state['checks'][$key] = $entry;
            } elseif ($entry !== null) {
                if (!empty($entry['alerted']) && $enabled) {
                    $recovered[$key] = $check + ['since' => $entry['since']];
                } else {
                    unset($state['checks'][$key]);
                }
            }
        }
        if (!$dbDown) {
            foreach (array_keys($state['checks']) as $key) {
                if (!isset($seen[$key])) {
                    unset($state['checks'][$key]);
                }
            }
        }

        $result = ['problems' => array_values($problems), 'recovered' => array_values($recovered), 'sent' => [], 'errors' => []];
        if ($problems || $recovered) {
            [$sent, $errors] = $this->notify($this->buildMessage($report, $result['problems'], $result['recovered']));
            $result['sent'] = $sent;
            $result['errors'] = $errors;
            // Delivered (or nobody to deliver to): remember it. All channels
            // failed: leave the state, the next run tries again.
            if ($sent || !$this->hasChannels()) {
                foreach (array_keys($problems) as $key) {
                    $state['checks'][$key]['alerted'] = true;
                }
                foreach (array_keys($recovered) as $key) {
                    unset($state['checks'][$key]);
                }
                $state['last_notification_at'] = $now;
            }
        }

        $state['last_run_at'] = $now;
        $state['last_status'] = $report['status'];
        $state['last_errors'] = $result['errors'];
        $this->config->set(self::STATE_KEY, $state);

        return $result;
    }

    /** Sends a test notification through every configured channel. @return array{0: string[], 1: string[]} sent channels, errors */
    public function sendTest(): array
    {
        return $this->notify([
            'subject' => '[Antispam] Test alertów',
            'text' => "To jest testowa wiadomość z modułu Stan systemu.\nAlerty działają." . $this->footer(),
            'payload' => ['type' => 'test', 'text' => 'Antispam: testowy alert ze Stanu systemu', 'instance' => $this->settings->getBaseUrl() ?: null],
        ]);
    }

    public function hasChannels(): bool
    {
        return $this->settings->getEffectiveAlertEmails() !== [] || $this->settings->getWebhookUrl() !== '';
    }

    /**
     * @return array{subject: string, text: string, payload: array}
     */
    public function buildMessage(array $report, array $problems, array $recovered): array
    {
        $labels = ['ok' => 'OK', 'degraded' => 'OSTRZEŻENIE', 'fail' => 'AWARIA'];
        if ($problems && $recovered) {
            $subject = sprintf('[Antispam] %d nowy(ch) problem(ów), %d przywrócone', count($problems), count($recovered));
        } elseif ($problems) {
            $subject = count($problems) === 1
                ? '[Antispam] Problem: ' . $problems[0]['label']
                : sprintf('[Antispam] %d kontrole nie przechodzą', count($problems));
        } else {
            $subject = count($recovered) === 1
                ? '[Antispam] Przywrócono: ' . $recovered[0]['label']
                : sprintf('[Antispam] Przywrócono %d kontrole', count($recovered));
        }

        $lines = [];
        if ($problems) {
            $lines[] = 'Nowe problemy:';
            foreach ($problems as $p) {
                $lines[] = sprintf('- [%s] %s: %s (od %s)', strtoupper($p['status']), $p['label'], $p['message'], $p['since']);
            }
            $lines[] = '';
        }
        if ($recovered) {
            $lines[] = 'Przywrócone:';
            foreach ($recovered as $r) {
                $lines[] = sprintf('- %s: %s', $r['label'], $r['message']);
            }
            $lines[] = '';
        }
        $lines[] = 'Stan ogólny: ' . ($labels[$report['status']] ?? $report['status']) . ' (' . $report['checked_at'] . ')';
        $text = implode("\n", $lines);

        $payload = [
            // "text" makes the payload readable by Slack / Mattermost / Teams
            // incoming webhooks; the other fields are for custom receivers.
            'text' => $subject . "\n" . $text,
            'type' => $problems ? 'problem' : 'recovery',
            'status' => $report['status'],
            'checked_at' => $report['checked_at'],
            'instance' => $this->settings->getBaseUrl() ?: null,
            'problems' => array_map(fn($p) => ['key' => $p['key'], 'label' => $p['label'], 'status' => $p['status'], 'message' => $p['message'], 'since' => $p['since']], $problems),
            'recovered' => array_map(fn($r) => ['key' => $r['key'], 'label' => $r['label'], 'since' => $r['since']], $recovered),
        ];

        return ['subject' => $subject, 'text' => $text . $this->footer(), 'payload' => $payload];
    }

    /** @return array{0: string[], 1: string[]} sent channels, errors */
    private function notify(array $message): array
    {
        $sent = [];
        $errors = [];

        $emails = $this->settings->getEffectiveAlertEmails();
        if ($emails) {
            $from = $this->settings->getFromEmail();
            try {
                $email = (new Email())
                    ->from(new Address((string)$from, 'Antispam Pancernapanda'))
                    ->subject($message['subject'])
                    ->text($message['text']);
                foreach ($emails as $to) {
                    $email->addTo($to);
                }
                $this->mailer->send($email);
                $sent[] = 'email';
            } catch (\Throwable $e) {
                $errors[] = 'E-mail: ' . $e->getMessage();
                $this->logger->error('Health alert e-mail failed: ' . $e->getMessage());
            }
        }

        $webhook = $this->settings->getWebhookUrl();
        if ($webhook !== '') {
            $error = $this->postJson($webhook, $message['payload']);
            if ($error === null) {
                $sent[] = 'webhook';
            } else {
                $errors[] = 'Webhook: ' . $error;
                $this->logger->error('Health alert webhook failed: ' . $error);
            }
        }

        if (!$emails && $webhook === '') {
            $errors[] = 'Brak odbiorcy alertów: ustaw e-mail (lub nadawcę raportu kwarantanny) albo webhook.';
        }
        return [$sent, $errors];
    }

    /** POSTs $payload as JSON. @return string|null error, null on a 2xx answer */
    protected function postJson(string $url, array $payload): ?string
    {
        if (!function_exists('curl_init')) {
            return 'brak rozszerzenia curl';
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => self::WEBHOOK_TIMEOUT,
            CURLOPT_TIMEOUT => self::WEBHOOK_TIMEOUT,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($body === false) {
            return $err ?: 'połączenie nieudane';
        }
        if ($code < 200 || $code >= 300) {
            return 'HTTP ' . $code . ': ' . mb_substr(trim((string)$body), 0, 200);
        }
        return null;
    }

    private function footer(): string
    {
        $base = $this->settings->getBaseUrl();
        return $base !== '' ? "\n\nSzczegóły: " . $base . '/system/status' : '';
    }
}
