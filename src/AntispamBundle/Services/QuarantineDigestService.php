<?php

namespace AntispamBundle\Services;

use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Twig\Environment;

/**
 * End-user quarantine digest (inspired by Barracuda's quarantine
 * notification): a periodic e-mail listing newly quarantined messages, each
 * with signed one-click "Deliver", "Deliver & always allow" and "Delete"
 * links that work without logging in.
 */
class QuarantineDigestService
{
    const DEFAULT_TTL_DAYS = 7;
    const DEFAULT_MAX_ITEMS = 50;
    const DEFAULT_LOOKBACK = '-24 hours';

    private $quarantine;
    private $tokens;
    private $twig;
    private $mailer;
    private $config;
    private $router;

    public function __construct(
        QuarantineService $quarantine,
        DigestTokenService $tokens,
        Environment $twig,
        MailerInterface $mailer,
        ConfigService $config,
        UrlGeneratorInterface $router
    ) {
        $this->quarantine = $quarantine;
        $this->tokens = $tokens;
        $this->twig = $twig;
        $this->mailer = $mailer;
        $this->config = $config;
        $this->router = $router;
    }

    public function isEnabled()
    {
        $v = $this->config->get('digest.enabled');
        return $v === true || in_array(strtolower((string)$v), ['1', 'true', 'yes', 'on'], true);
    }

    /**
     * Is the digest on for this mailbox (getMailboxes() row)? Its own setting
     * (Ustawienia skrzynki) wins over the global switch; with $force an
     * inheriting mailbox counts as on (--force, "Zapisz i wyślij teraz"), an
     * explicit "off" never does.
     */
    public function isEnabledFor(array $mailbox, bool $force = false): bool
    {
        $own = $mailbox['digest_enabled'] ?? null;
        if ($own !== null) {
            return (bool)$own;
        }
        return $force || $this->isEnabled();
    }

    /** Does at least one mailbox get a digest (global switch or its own)? */
    public function hasEnabledMailbox(): bool
    {
        foreach ($this->quarantine->getMailboxes() as $mailbox) {
            if ($this->isEnabledFor($mailbox)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A mailbox with its own send hour H is due at the first run at or after
     * H:00 (server time) that has not sent it yet today, so a missed hourly
     * run catches up later the same day. Mailboxes without one go out on
     * every run (the global schedule: cron / DIGEST_HOUR).
     */
    public function isDue(array $mailbox, ?\DateTimeImmutable $now = null): bool
    {
        $hour = $mailbox['digest_hour'] ?? null;
        if ($hour === null) {
            return true;
        }
        $now = $now ?? new \DateTimeImmutable();
        $slot = $now->setTime((int)$hour, 0);
        if ($now < $slot) {
            return false;
        }
        $last = $this->getLastSent($mailbox['key']);
        return $last === null || $last < $slot;
    }

    /**
     * Public base URL of this application (links in the e-mail must be
     * absolute and reachable by the recipient, e.g. https://antispam.firma.pl).
     */
    public function getBaseUrl()
    {
        return rtrim(trim((string)$this->config->get('digest.base_url')), '/');
    }

    public function getFromEmail()
    {
        return trim((string)$this->config->get('digest.from_email'));
    }

    public function getFromName()
    {
        return trim((string)$this->config->get('digest.from_name')) ?: 'Pancernapanda antispam';
    }

    public function getTtlDays()
    {
        $v = (int)$this->config->get('digest.token_ttl_days');
        return $v > 0 ? $v : self::DEFAULT_TTL_DAYS;
    }

    public function getMaxItems()
    {
        $v = (int)$this->config->get('digest.max_items');
        return $v > 0 ? $v : self::DEFAULT_MAX_ITEMS;
    }

    /**
     * @return string[] configuration problems that prevent sending (empty = OK)
     */
    public function configurationErrors()
    {
        $errors = [];
        if (!preg_match('~^https?://[^/\s]+~i', $this->getBaseUrl())) {
            $errors[] = 'Nie ustawiono publicznego adresu aplikacji (np. https://antispam.example.com).';
        }
        if (!filter_var($this->getFromEmail(), FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Brak lub nieprawidłowy adres nadawcy.';
        }
        if ($this->tokens->usesDefaultSecret()) {
            $errors[] = 'APP_SECRET ma wartość domyślną, więc linki w raporcie dałoby się podrobić. Ustaw losowy APP_SECRET (zmienna środowiskowa).';
        }
        return $errors;
    }

    public function getLastSent($mailboxKey)
    {
        $ts = (int)$this->config->get('digest.last_sent.' . $mailboxKey);
        return $ts > 0 ? (new \DateTimeImmutable())->setTimestamp($ts) : null;
    }

    /**
     * Build the digest for one mailbox: items received since $since (default:
     * since the previous digest, or the last 24 hours), each with action URLs.
     *
     * @return array ['mailbox' => array, 'items' => array, 'total' => int, 'since' => \DateTimeImmutable|null]
     */
    public function build(array $mailbox, ?\DateTimeInterface $since = null)
    {
        if ($since === null) {
            $since = $this->getLastSent($mailbox['key']) ?: new \DateTimeImmutable(self::DEFAULT_LOOKBACK);
        }
        $items = $this->quarantine->listItems($mailbox['key'], $since, 500);
        $total = count($items);
        $items = array_slice($items, 0, $this->getMaxItems());

        $ttl = $this->getTtlDays() * 86400;
        foreach ($items as &$item) {
            // IMAP UIDs are only unique within one UIDVALIDITY: bind the link to it.
            $meta = ['sender' => $item['from'], 'subject' => $item['subject'], 'account' => $mailbox['account_email'], 'uidvalidity' => $item['uidvalidity'] ?? null];
            $item['links'] = [];
            // Never offer to permanently trust an impersonator or a malware sender:
            // no whitelist token is minted, so the action can't be performed.
            $item['allow_whitelist'] = !self::isHighRisk($item['reasons']);
            foreach (DigestTokenService::actions() as $action) {
                if ($action === DigestTokenService::ACTION_WHITELIST && !$item['allow_whitelist']) {
                    continue;
                }
                $token = $this->tokens->create($mailbox['key'], $item['id'], $action, $ttl, $meta);
                $item['links'][$action] = $this->getBaseUrl()
                    . $this->router->generate('antispam_quarantine_action', ['token' => $token], UrlGeneratorInterface::ABSOLUTE_PATH);
            }
            $item['reason_labels'] = self::reasonLabels($item['reasons']);
        }
        unset($item);

        return ['mailbox' => $mailbox, 'items' => $items, 'total' => $total, 'since' => $since];
    }

    public function renderHtml(array $digest)
    {
        return $this->twig->render('@Antispam/Digest/email.html.twig', $digest + ['ttl_days' => $this->getTtlDays()]);
    }

    public function renderText(array $digest)
    {
        return $this->twig->render('@Antispam/Digest/email.txt.twig', $digest + ['ttl_days' => $this->getTtlDays()]);
    }

    /**
     * Send one digest. Returns the number of accepted recipients (1).
     */
    public function send(array $digest)
    {
        $recipient = $digest['mailbox']['recipient'];
        if (!filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
            throw new \RuntimeException(sprintf('Mailbox %s has no valid digest recipient', $digest['mailbox']['key']));
        }
        $message = (new Email())
            ->subject(sprintf('Kwarantanna: %d %s do przejrzenia', $digest['total'], self::pluralMessages($digest['total'])))
            ->from(new Address($this->getFromEmail(), $this->getFromName()))
            ->to($recipient)
            ->html($this->renderHtml($digest))
            ->text($this->renderText($digest));
        // Lets mail filters / rules recognise the digest itself.
        $message->getHeaders()->addTextHeader('X-Antispam-Digest', '1');

        // Throws on a transport failure; sendAll() reports it as an error.
        $this->mailer->send($message);

        return 1;
    }

    /**
     * Build and send digests for all (or one) mailboxes. Empty digests are
     * skipped. The "last sent" marker only moves forward when a digest was
     * actually delivered (or there was nothing to send).
     *
     * Per-mailbox settings: a mailbox switched off is reported as `disabled`,
     * one with its own send hour that is not due yet as `not-due`.
     *
     * @param bool $force          inheriting mailboxes count as enabled even with the global switch off
     * @param bool $scheduledOnly  only mailboxes with their own send hour (the hourly run)
     * @param bool $ignoreSchedule send regardless of the mailboxes' send hours ("send now", --mailbox)
     *
     * @return array list of ['key','recipient','count','status','error']
     */
    public function sendAll($onlyKey = null, ?\DateTimeInterface $since = null, $dryRun = false, bool $force = false, bool $scheduledOnly = false, bool $ignoreSchedule = false, ?\DateTimeImmutable $now = null)
    {
        $report = [];
        foreach ($this->quarantine->getMailboxes() as $mailbox) {
            if ($onlyKey !== null && $mailbox['key'] !== $onlyKey) {
                continue;
            }
            if ($scheduledOnly && ($mailbox['digest_hour'] ?? null) === null) {
                continue;
            }
            $startedAt = time();
            $row = ['key' => $mailbox['key'], 'recipient' => $mailbox['recipient'], 'count' => 0, 'status' => 'skipped', 'error' => null];
            if (!$this->isEnabledFor($mailbox, $force)) {
                if (!$scheduledOnly) {
                    $report[] = ['status' => 'disabled'] + $row;
                }
                continue;
            }
            if (!$ignoreSchedule && !$this->isDue($mailbox, $now)) {
                if (!$scheduledOnly) {
                    $report[] = ['status' => 'not-due'] + $row;
                }
                continue;
            }
            try {
                $digest = $this->build($mailbox, $since);
                $row['count'] = $digest['total'];
                if ($digest['total'] === 0) {
                    $row['status'] = 'empty';
                } elseif ($dryRun) {
                    $row['status'] = 'dry-run';
                } else {
                    $row['status'] = $this->send($digest) > 0 ? 'sent' : 'rejected';
                }
                if (!$dryRun && in_array($row['status'], ['sent', 'empty'], true)) {
                    $this->config->set('digest.last_sent.' . $mailbox['key'], (string)$startedAt);
                }
            } catch (\Throwable $e) {
                $row['status'] = 'error';
                $row['error'] = $e->getMessage();
            }
            $report[] = $row;
        }
        return $report;
    }

    /**
     * Reasons that make "always accept this sender" unsafe. score_unknown
     * (QuarantineService::REASON_SCORE_UNKNOWN: no score log row found) counts
     * too - without the reasons we can't tell, so fail closed.
     */
    public static function isHighRisk(array $reasons)
    {
        foreach ($reasons as $r) {
            $rule = (string)($r['rule'] ?? '');
            if (preg_match('/^(score_unknown$|impersonation_|lookalike_domain|internal_domain_spoof|display_name_embedded_address|attachment_|clamav|virustotal|url_safebrowsing|url_dbl|cert_hole)/', $rule)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Polish plural of "wiadomość": 1 wiadomość, 2-4 wiadomości, 5+ wiadomości.
     */
    public static function pluralMessages($n)
    {
        return (int)$n === 1 ? 'wiadomość' : 'wiadomości';
    }

    /**
     * Human-readable (Polish, end-user facing) labels for the most significant score reasons.
     */
    public static function reasonLabels(array $reasons, $max = 3)
    {
        $labels = [
            'impersonation_vip' => 'Podszywa się pod chronioną osobę',
            'impersonation_display_address' => 'Nazwa nadawcy pokazuje inny adres',
            'display_name_embedded_address' => 'Nazwa nadawcy zawiera adres e-mail',
            'lookalike_domain' => 'Domena nadawcy łudząco podobna do Twojej',
            'internal_domain_spoof' => 'Sfałszowana własna domena',
            'url_text_mismatch' => 'Link prowadzi pod inny adres niż pokazuje',
            'url_ip_host' => 'Link do adresu IP',
            'url_shortener' => 'Skrócony link',
            'url_punycode' => 'Link z domeną IDN (możliwa podróbka)',
            'url_dbl' => 'Link do domeny z czarnej listy',
            'url_safebrowsing' => 'Link oznaczony przez Google Safe Browsing',
            'attachment_blocked' => 'Zablokowany typ załącznika',
            'attachment_double_extension' => 'Załącznik z podwójnym rozszerzeniem',
            'attachment_bidi_filename' => 'Ukryte znaki w nazwie załącznika',
            'attachment_disguised_executable' => 'Program udający dokument',
            'attachment_archive_blocked' => 'Archiwum zawierające program',
            'attachment_office_macro' => 'Dokument z makrami',
            'attachment_pdf_active' => 'PDF z aktywną zawartością',
            'attachment_encrypted_archive' => 'Archiwum zabezpieczone hasłem',
            'attachment_encrypted_office' => 'Dokument zabezpieczony hasłem',
            'spf_fail' => 'Serwer nadawcy nieautoryzowany (SPF)',
            'dkim_fail' => 'Brak lub błędny podpis (DKIM)',
            'dmarc_fail' => 'Niezgodność DMARC',
            'from_reply_mismatch' => 'Odpowiedzi trafiają do innej domeny',
            'suspicious_subject' => 'Podejrzany temat',
            'all_caps_subject' => 'Podejrzany temat',
            'dnsbl' => 'Nadawca na czarnej liście (DNSBL)',
            'blacklist' => 'Zablokowana domena nadawcy',
            'email_blacklist' => 'Zablokowany adres nadawcy',
            'shared_feed' => 'Znany spam',
            'cert_hole' => 'Domena z Listy Ostrzeżeń CERT Polska (phishing)',
            'clamav' => 'Wykryto wirusa',
            'virustotal' => 'Złośliwy załącznik',
            'score_unknown' => 'Brak zapisanej oceny - zachowaj ostrożność',
        ];
        usort($reasons, function ($a, $b) {
            return (int)($b['score'] ?? 0) - (int)($a['score'] ?? 0);
        });
        $out = [];
        foreach ($reasons as $r) {
            $rule = (string)($r['rule'] ?? '');
            $base = strtok($rule, ':');
            $label = $labels[$base] ?? null;
            if ($label !== null && !in_array($label, $out, true)) {
                $out[] = $label;
            }
            if (count($out) >= $max) {
                break;
            }
        }
        return $out;
    }
}
