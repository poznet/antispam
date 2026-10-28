<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\PhishingReport;
use AntispamBundle\Repository\PhishingReportRepository;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Exception\RfcComplianceException;
use Symfony\Component\Mime\Part\DataPart;

/**
 * Forwards a stored phishing report to CERT Polska (or a SOC address set in
 * the panel): a short Polish note with the analysis summary plus the original
 * source, unmodified, as a message/rfc822 attachment.
 *
 * cert@cert.pl is CERT Polska's incident address ("The preferred method for
 * contacting CERT Polska is via e-mail at <cert@cert.pl>", RFC 2350 v2.1 of
 * 13 March 2025, https://cert.pl/en/uploads/misc/rfc2350.txt); the web form
 * https://incydent.cert.pl/ is the alternative.
 *
 * Settings live in the `config` table under `phishing_forward.*`.
 */
class PhishingForwardService
{
    const DEFAULT_RECIPIENT = 'cert@cert.pl';
    const CERT_FORM_URL = 'https://incydent.cert.pl/';

    const DEFAULT_MAX_KB = 10240;
    const MIN_MAX_KB = 64;
    const MAX_MAX_KB = 25600;
    const MAX_ADDRESSES = 5;
    const MAX_NOTE = 2000;
    const MAX_AUTO_MINUTES = 10080;
    /** Reports sent per automatic run - a flood of reports must not become a flood of e-mail. */
    const AUTO_BATCH = 20;
    /** An attempt that neither succeeded nor failed within this time is considered dead. */
    const STALE_ATTEMPT_MINUTES = 10;
    /** Max line length (octets, without CRLF) allowed by RFC 5322 for 8bit content. */
    const MAX_LINE = 998;
    /** Header-only fallback is capped too (hostile messages may be "all header"). */
    const MAX_HEADERS_BYTES = 262144;

    const DEFAULT_NOTE = "Dzień dobry,\n\nprzekazuję wiadomość zgłoszoną przez użytkownika jako próba phishingu (zgłoszenie #{id}). "
        . "Oryginalna wiadomość z pełnymi nagłówkami jest w załączniku (message/rfc822).";

    public function __construct(
        private ConfigService $config,
        private MailerInterface $mailer,
        private EntityManagerInterface $em,
        private PhishingReportService $phishing,
        private ?LoggerInterface $logger = null,
        /** null = not checked (tests); '' or null:// = mail is discarded, so refuse to "send". */
        #[Autowire('%env(MAILER_DSN)%')]
        private ?string $mailerDsn = null,
    ) {
    }

    /**
     * Current settings with defaults. Recipients default to CERT Polska only
     * while the setting was never saved - an admin may clear it to disable
     * forwarding.
     */
    public function getSettings(): array
    {
        $c = $this->config;
        $recipients = $c->get('phishing_forward.recipients');
        $maxKb = (int)$c->get('phishing_forward.max_kb');

        return [
            'recipients' => $recipients === null ? [self::DEFAULT_RECIPIENT] : self::splitAddresses((string)$recipients),
            'from_email' => trim((string)$c->get('phishing_forward.from_email')),
            'from_name' => trim((string)$c->get('phishing_forward.from_name')),
            'cc' => self::splitAddresses((string)$c->get('phishing_forward.cc')),
            'note' => (string)($c->get('phishing_forward.note') ?? self::DEFAULT_NOTE),
            'include_reporter' => (string)$c->get('phishing_forward.include_reporter') === '1',
            'max_kb' => $maxKb > 0 ? $maxKb : self::DEFAULT_MAX_KB,
            'auto_minutes' => max(0, (int)$c->get('phishing_forward.auto_minutes')),
            'auto_since' => $c->get('phishing_forward.auto_since') ? new \DateTime((string)$c->get('phishing_forward.auto_since')) : null,
        ];
    }

    /**
     * Validate the settings form.
     *
     * @return array{0: array, 1: string[]} [normalized settings, errors]
     */
    public function validateSettings(array $in): array
    {
        $errors = [];
        $out = [];

        $out['recipients'] = self::splitAddresses((string)($in['recipients'] ?? ''));
        foreach ($out['recipients'] as $a) {
            if (!self::isEmail($a)) {
                $errors[] = 'Nieprawidłowy adres odbiorcy: ' . $a;
            }
        }
        if (count($out['recipients']) > self::MAX_ADDRESSES) {
            $errors[] = 'Najwyżej ' . self::MAX_ADDRESSES . ' odbiorców.';
        }

        $out['cc'] = self::splitAddresses((string)($in['cc'] ?? ''));
        foreach ($out['cc'] as $a) {
            if (!self::isEmail($a)) {
                $errors[] = 'Nieprawidłowy adres kopii (CC): ' . $a;
            }
        }
        if (count($out['cc']) > self::MAX_ADDRESSES) {
            $errors[] = 'Najwyżej ' . self::MAX_ADDRESSES . ' adresów w kopii.';
        }

        $out['from_email'] = trim((string)($in['from_email'] ?? ''));
        if ($out['from_email'] !== '' && !self::isEmail($out['from_email'])) {
            $errors[] = 'Nieprawidłowy adres nadawcy: ' . $out['from_email'];
        }
        $out['from_name'] = mb_substr(trim(preg_replace('/[\r\n\t]+/', ' ', (string)($in['from_name'] ?? ''))), 0, 100);

        $note = str_replace("\r\n", "\n", (string)($in['note'] ?? ''));
        if (mb_strlen($note) > self::MAX_NOTE) {
            $errors[] = 'Notatka może mieć najwyżej ' . self::MAX_NOTE . ' znaków.';
        }
        $out['note'] = trim($note);

        $out['include_reporter'] = !empty($in['include_reporter']);

        $maxKb = filter_var($in['max_kb'] ?? self::DEFAULT_MAX_KB, FILTER_VALIDATE_INT);
        if ($maxKb === false || $maxKb < self::MIN_MAX_KB || $maxKb > self::MAX_MAX_KB) {
            $errors[] = 'Limit rozmiaru musi być liczbą od ' . self::MIN_MAX_KB . ' do ' . self::MAX_MAX_KB . ' KiB.';
            $maxKb = self::DEFAULT_MAX_KB;
        }
        $out['max_kb'] = $maxKb;

        $auto = filter_var(($in['auto_minutes'] ?? '') === '' ? 0 : $in['auto_minutes'], FILTER_VALIDATE_INT);
        if ($auto === false || $auto < 0 || $auto > self::MAX_AUTO_MINUTES) {
            $errors[] = 'Opóźnienie automatycznej wysyłki musi być liczbą minut od 0 (wyłączone) do ' . self::MAX_AUTO_MINUTES . '.';
            $auto = 0;
        }
        $out['auto_minutes'] = $auto;
        if ($auto > 0 && !$out['recipients']) {
            $errors[] = 'Automatyczna wysyłka wymaga co najmniej jednego odbiorcy.';
        }
        if ($auto > 0 && $out['from_email'] === '' && !self::isEmail($this->fallbackFrom())) {
            $errors[] = 'Automatyczna wysyłka wymaga adresu nadawcy.';
        }

        return [$out, $errors];
    }

    /** Store settings already checked by validateSettings(). */
    public function saveSettings(array $s): void
    {
        $c = $this->config;
        $wasAuto = $this->getSettings()['auto_minutes'] > 0;
        $c->set('phishing_forward.recipients', implode(', ', $s['recipients']));
        $c->set('phishing_forward.cc', implode(', ', $s['cc']));
        $c->set('phishing_forward.from_email', $s['from_email']);
        $c->set('phishing_forward.from_name', $s['from_name']);
        $c->set('phishing_forward.note', $s['note']);
        $c->set('phishing_forward.include_reporter', $s['include_reporter'] ? '1' : '0');
        $c->set('phishing_forward.max_kb', (string)$s['max_kb']);
        $c->set('phishing_forward.auto_minutes', (string)$s['auto_minutes']);
        // Switching automatic mode on only covers reports from now on - the
        // backlog is never mass-sent behind the admin's back.
        if ($s['auto_minutes'] > 0 && !$wasAuto) {
            $c->set('phishing_forward.auto_since', (new \DateTime())->format('Y-m-d H:i:s'));
        }
    }

    /** Why forwarding cannot work right now (empty = ready). */
    public function configurationErrors(): array
    {
        $s = $this->getSettings();
        $errors = [];
        if (!$s['recipients']) {
            $errors[] = 'Brak odbiorcy - ustaw adres CERT Polska lub SOC w ustawieniach przekazywania.';
        }
        if ($this->mailerDsn !== null && (trim($this->mailerDsn) === '' || str_starts_with(trim($this->mailerDsn), 'null://'))) {
            $errors[] = 'Wysyłka poczty jest wyłączona (MAILER_DSN pusty lub null://) - ustaw serwer SMTP.';
        }
        if (!self::isEmail($this->fromEmail($s))) {
            $errors[] = 'Brak poprawnego adresu nadawcy (ustawienia przekazywania albo raportu kwarantanny).';
        }
        return $errors;
    }

    /** This report, or another copy of the same message, already forwarded - or null. */
    public function previouslyForwarded(PhishingReport $report): ?PhishingReport
    {
        if ($report->getForwardedAt()) {
            return $report;
        }
        return $this->repository()->findForwardedCopy($report);
    }

    /**
     * Send one report. $resend must be true when it (or a copy) was already
     * forwarded - the caller asked the admin to confirm.
     *
     * @return array{status: string, error: ?string} status: sent | failed | skipped
     */
    public function forward(PhishingReport $report, bool $resend = false): array
    {
        if ($errors = $this->configurationErrors()) {
            return ['status' => 'skipped', 'error' => implode(' ', $errors)];
        }
        if ($report->getStatus() === PhishingReport::STATUS_FALSE_POSITIVE) {
            return ['status' => 'skipped', 'error' => 'Zgłoszenie oznaczono jako „to nie phishing”.'];
        }
        if (!$resend && $this->previouslyForwarded($report)) {
            return ['status' => 'skipped', 'error' => 'Ta wiadomość została już wysłana.'];
        }

        $now = new \DateTime();
        $stale = new \DateTime('-' . self::STALE_ATTEMPT_MINUTES . ' minutes');
        if (!$this->repository()->claimForForward((int)$report->getId(), $now, $stale, $resend)) {
            return ['status' => 'skipped', 'error' => 'Wysyłka tego zgłoszenia już trwa albo właśnie się zakończyła.'];
        }
        $report->markForwardAttempt($now);

        $settings = $this->getSettings();
        try {
            $email = $this->buildEmail($report, $settings);
            $this->mailer->send($email);
        } catch (TransportExceptionInterface | RfcComplianceException $e) {
            $report->markForwardFailed($e->getMessage());
            $this->em->flush();
            $this->logger?->error('Phishing report forward failed', ['id' => $report->getId(), 'error' => $e->getMessage()]);
            return ['status' => 'failed', 'error' => $report->getForwardError()];
        }

        $report->markForwarded(array_merge($settings['recipients'], $settings['cc']), $now);
        if (in_array($report->getStatus(), [PhishingReport::STATUS_NEW, PhishingReport::STATUS_CONFIRMED], true)) {
            $report->setStatus(PhishingReport::STATUS_REPORTED);
        }
        $this->em->flush();
        $this->logger?->info('Phishing report forwarded', ['id' => $report->getId(), 'to' => $report->getForwardedTo()]);

        return ['status' => 'sent', 'error' => null];
    }

    /**
     * Automatic mode: forward reports older than the configured delay that
     * the admin did not mark as false positive. No-op while disabled.
     *
     * @return array<int, array{status: string, error: ?string}> report id => result
     */
    public function forwardPending(): array
    {
        $s = $this->getSettings();
        if ($s['auto_minutes'] <= 0 || !$s['auto_since'] || $this->configurationErrors()) {
            return [];
        }
        $before = new \DateTime('-' . $s['auto_minutes'] . ' minutes');
        $results = [];
        $sent = [];
        foreach ($this->repository()->findAutoForwardCandidates($s['auto_since'], $before, self::AUTO_BATCH) as $report) {
            // The same message reported by several mailboxes goes out once.
            $r = isset($sent[$report->getSha256()])
                ? ['status' => 'skipped', 'error' => 'Ta wiadomość została już wysłana.']
                : $this->forward($report);
            if ($r['status'] === 'sent') {
                $sent[$report->getSha256()] = true;
            } elseif ($r['status'] === 'skipped' && !$report->getForwardAttemptedAt()) {
                // Looked at once - do not pick it up (and fill the batch) on every run.
                $report->markForwardAttempt(new \DateTime());
                $this->em->flush();
            }
            $results[$report->getId()] = $r;
        }
        return $results;
    }

    /** The outgoing e-mail: note + original as message/rfc822 (or its headers when too big). */
    public function buildEmail(PhishingReport $report, ?array $settings = null): Email
    {
        $s = $settings ?? $this->getSettings();
        $raw = $report->getRaw();
        $tooBig = strlen($raw) > $s['max_kb'] * 1024;

        $email = (new Email())
            ->from(new Address($this->fromEmail($s), $s['from_name'] ?: 'Pancernapanda antispam'))
            ->to(...$s['recipients'])
            ->subject(self::subjectFor($report))
            ->text($this->noteFor($report, $s, $tooBig));
        if ($s['cc']) {
            $email->cc(...$s['cc']);
        }

        if ($tooBig) {
            // Cutting the message would corrupt it; send the full headers (what
            // CERT needs to trace it) as text/rfc822-headers (RFC 6522).
            $email->addPart(new DataPart(self::headersOf($raw), 'phishing-' . $report->getId() . '-naglowki.txt', 'text/rfc822-headers', 'base64'));
        } else {
            // Original bytes, unmodified. message/rfc822 must not be base64
            // (RFC 2046 5.2.1) unless it cannot be sent as 8bit at all.
            $encoding = self::fitsEightBit($raw) ? '8bit' : 'base64';
            $email->addPart(new DataPart($raw, 'phishing-' . $report->getId() . '.eml', 'message/rfc822', $encoding));
        }

        return $email;
    }

    public static function subjectFor(PhishingReport $report): string
    {
        $subject = trim(preg_replace('/\s+/u', ' ', (string)$report->getSubject()));
        return 'Phishing: ' . ($subject === '' ? '(bez tematu)' : mb_substr($subject, 0, 200));
    }

    private function noteFor(PhishingReport $report, array $s, bool $tooBig): string
    {
        $a = $this->phishing->analyze($report);
        $intro = strtr($s['note'] !== '' ? $s['note'] : self::DEFAULT_NOTE, [
            '{id}' => (string)$report->getId(),
            '{subject}' => (string)$report->getSubject(),
            '{sender}' => (string)$report->getSender(),
        ]);

        $lines = [$intro, '', 'Szczegóły (zgłoszenie #' . $report->getId() . '):'];
        $lines[] = '- Nadawca: ' . trim(($report->getSenderName() ? $report->getSenderName() . ' ' : '') . '<' . ($report->getSender() ?: '?') . '>');
        if ($report->getReplyTo()) {
            $lines[] = '- Reply-To: ' . $report->getReplyTo();
        }
        if ($report->getReturnPath()) {
            $lines[] = '- Return-Path: ' . $report->getReturnPath();
        }
        $lines[] = '- Temat: ' . ($report->getSubject() ?: '(bez tematu)');
        if (!empty($a['date'])) {
            $lines[] = '- Data wiadomości: ' . $a['date'];
        }
        if ($report->getConnectingIp()) {
            $lines[] = '- Serwer nadawcy (IP): ' . $report->getConnectingIp();
        }
        $auth = [];
        foreach (['spf', 'dkim', 'dmarc'] as $k) {
            $auth[] = strtoupper($k) . '=' . ($a['auth'][$k] ?? 'brak');
        }
        $lines[] = '- Uwierzytelnienie: ' . implode(', ', $auth);
        if (!empty($a['link_hosts'])) {
            $lines[] = '- Domeny w linkach: ' . implode(', ', array_slice(array_keys($a['link_hosts']), 0, 15));
        }
        $lines[] = '- Zgłoszono: ' . $report->getCreatedAt()->format('Y-m-d H:i')
            . ($s['include_reporter'] ? ' przez skrzynkę ' . $report->getAccountEmail() : '');
        $lines[] = '- SHA-256 oryginału: ' . $report->getSha256();

        if (!empty($a['flags'])) {
            $lines[] = '';
            $lines[] = 'Sygnały ostrzegawcze z automatycznej analizy:';
            foreach ($a['flags'] as $f) {
                $lines[] = '- ' . $f;
            }
        }

        if ($tooBig) {
            $lines[] = '';
            $lines[] = sprintf('UWAGA: wiadomość ma %.1f KiB i przekracza limit %d KiB, dlatego w załączniku są tylko jej nagłówki (text/rfc822-headers). Pełną treść możemy przekazać na prośbę.', strlen($report->getRaw()) / 1024, $s['max_kb']);
        } elseif ($report->isTruncated()) {
            $lines[] = '';
            $lines[] = 'UWAGA: program pocztowy użytkownika obciął wiadomość przy zgłoszeniu (limit wysyłki wtyczki) - w załączniku może brakować części treści lub załączników.';
        }

        return implode("\n", $lines) . "\n";
    }

    private function fromEmail(array $s): string
    {
        return $s['from_email'] !== '' ? $s['from_email'] : $this->fallbackFrom();
    }

    private function fallbackFrom(): string
    {
        return trim((string)$this->config->get('digest.from_email'));
    }

    private function repository(): PhishingReportRepository
    {
        return $this->em->getRepository(PhishingReport::class);
    }

    /** @return string[] */
    public static function splitAddresses(string $value): array
    {
        $out = [];
        foreach (preg_split('/[\s,;]+/', $value, -1, PREG_SPLIT_NO_EMPTY) as $a) {
            $out[strtolower($a)] = $a;
        }
        return array_values($out);
    }

    public static function isEmail(string $value): bool
    {
        return $value !== '' && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }

    /** Header block of a raw message (up to the first empty line). */
    public static function headersOf(string $raw): string
    {
        $headers = preg_match('/\r?\n\r?\n/', $raw, $m, PREG_OFFSET_CAPTURE) ? substr($raw, 0, $m[0][1]) : $raw;
        // A message without a body separator would otherwise be sent whole.
        return substr($headers, 0, self::MAX_HEADERS_BYTES) . "\r\n";
    }

    private static function fitsEightBit(string $raw): bool
    {
        if (strpos($raw, "\0") !== false) {
            return false;
        }
        foreach (preg_split('/\r?\n/', $raw) as $line) {
            if (strlen($line) > self::MAX_LINE) {
                return false;
            }
        }
        return true;
    }
}
