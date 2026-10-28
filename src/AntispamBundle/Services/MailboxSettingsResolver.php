<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Per-mailbox settings: account override -> global setting.
 *
 * The single place that knows which settings a mailbox (Konta) may override
 * and what it inherits otherwise. Every consumer asks it: the IMAP pipeline
 * and the plugin check (via within(), which scopes ScoringService), the
 * retroactive blacklist pass, the SSH agent (scan flags and synced settings)
 * and the quarantine digest. The legacy mailbox from the "E-mail" settings
 * has no overrides - global() is its settings.
 */
class MailboxSettingsResolver
{
    /** Override fields of the account form / backup, in display order. */
    public const FIELDS = ['spam_threshold', 'quarantine_threshold', 'scoring_enabled', 'digest_enabled', 'digest_recipient', 'digest_hour'];

    /** Polish labels of FIELDS for the panel. */
    public const LABELS = [
        'spam_threshold' => 'próg spamu',
        'quarantine_threshold' => 'próg kwarantanny',
        'scoring_enabled' => 'punktacja',
        'digest_enabled' => 'raport kwarantanny',
        'digest_recipient' => 'odbiorca raportu',
        'digest_hour' => 'godzina raportu',
    ];

    public const MAX_THRESHOLD = 1000;

    public function __construct(
        private ScoringService $scoring,
        private ConfigService $config,
        private EntityManagerInterface $em,
    ) {
    }

    /** Global settings - also the settings of the legacy mailbox. */
    public function global(): MailboxSettings
    {
        $email = trim((string)$this->config->get('email'));
        $recipient = trim((string)$this->config->get('digest.imap_recipient')) ?: $email;

        return new MailboxSettings(
            $this->scoring->getGlobalSpamThreshold(),
            $this->scoring->getGlobalQuarantineThreshold(),
            $this->scoring->isGlobalScoringEnabled(),
            self::truthy($this->config->get('delete')),
            $this->isGlobalDigestEnabled(),
            $recipient !== '' ? $recipient : null,
            null,
        );
    }

    /** Effective settings of an account (null = global / legacy mailbox). */
    public function forAccount(?Account $account): MailboxSettings
    {
        if ($account === null) {
            return $this->global();
        }
        $overrides = $account->getSettingsOverrides();

        return new MailboxSettings(
            $account->getSpamThreshold() ?? $this->scoring->getGlobalSpamThreshold(),
            $account->getQuarantineThreshold() ?? $this->scoring->getGlobalQuarantineThreshold(),
            $account->getScoringEnabled() ?? $this->scoring->isGlobalScoringEnabled(),
            // Spam action has always been per account (no inheritance): IMAP
            // accounts move or delete as set on the form; the Maildir agent
            // never deletes spam.
            !$account->isSsh() && (bool)$account->getDeleteSpam(),
            $account->getDigestEnabled() ?? $this->isGlobalDigestEnabled(),
            $account->getDigestRecipient() ?? ((string)$account->getEmail() !== '' ? (string)$account->getEmail() : null),
            $account->getDigestHour(),
            $overrides,
        );
    }

    /**
     * Settings of the account with this e-mail (first by id), or the global
     * ones when no account has it (e.g. the legacy mailbox).
     */
    public function forEmail(?string $email): MailboxSettings
    {
        if ($email === null || trim($email) === '') {
            return $this->global();
        }
        $account = $this->em->getRepository(Account::class)->findOneBy(['email' => trim($email)], ['id' => 'ASC']);

        return $this->forAccount($account instanceof Account ? $account : null);
    }

    /**
     * Run $fn with the mailbox's thresholds / scoring switch in effect for
     * everything that reads them from ScoringService.
     */
    public function within(Account|MailboxSettings|null $mailbox, callable $fn)
    {
        $settings = $mailbox instanceof MailboxSettings ? $mailbox : $this->forAccount($mailbox);

        return $this->scoring->withMailbox($settings, $fn);
    }

    public function isGlobalDigestEnabled(): bool
    {
        return self::truthy($this->config->get('digest.enabled'));
    }

    /**
     * Parse and validate the override fields of the account form. Empty =
     * inherit (null). Thresholds are checked against each other with the
     * inherited global value filling in the one that is not overridden, so
     * an account cannot end up with quarantine >= spam at save time.
     *
     * @return array{0: array<string, int|bool|string|null>, 1: string[]} [values, errors]
     */
    public function parseOverrides(array $data): array
    {
        return self::parseOverrideValues($data, $this->scoring->getGlobalSpamThreshold(), $this->scoring->getGlobalQuarantineThreshold());
    }

    /**
     * parseOverrides() without the service: form strings or backup JSON
     * values (bool / int / null). With null global thresholds quarantine <
     * spam is only checked when both are overridden.
     *
     * @return array{0: array<string, int|bool|string|null>, 1: string[]} [values, errors]
     */
    public static function parseOverrideValues(array $data, ?int $globalSpam = null, ?int $globalQuarantine = null): array
    {
        $values = array_fill_keys(self::FIELDS, null);
        $errors = [];
        foreach (self::FIELDS as $field) {
            $v = $data[$field] ?? null;
            $data[$field] = is_bool($v) ? ($v ? '1' : '0') : (is_scalar($v) ? (string)$v : '');
        }

        foreach (['spam_threshold' => [1, 'Próg spamu'], 'quarantine_threshold' => [0, 'Próg kwarantanny']] as $field => [$min, $label]) {
            $raw = trim($data[$field]);
            if ($raw === '') {
                continue;
            }
            if (!preg_match('/^\d{1,4}$/', $raw) || (int)$raw < $min || (int)$raw > self::MAX_THRESHOLD) {
                $errors[] = sprintf('%s skrzynki: podaj liczbę od %d do %d albo zostaw puste (dziedzicz).', $label, $min, self::MAX_THRESHOLD);
                continue;
            }
            $values[$field] = (int)$raw;
        }
        if (!$errors && ($values['spam_threshold'] !== null || $values['quarantine_threshold'] !== null)) {
            $spam = $values['spam_threshold'] ?? $globalSpam;
            $quarantine = $values['quarantine_threshold'] ?? $globalQuarantine;
            if ($spam !== null && $quarantine !== null && $quarantine >= $spam) {
                $errors[] = sprintf('Próg kwarantanny (%d) musi być niższy niż próg spamu (%d) - wartości puste są dziedziczone z ustawień globalnych.', $quarantine, $spam);
                $values['spam_threshold'] = $values['quarantine_threshold'] = null;
            }
        }

        foreach (['scoring_enabled' => 'Punktacja', 'digest_enabled' => 'Raport kwarantanny'] as $field => $label) {
            $raw = (string)($data[$field] ?? '');
            if ($raw === '') {
                continue;
            }
            if (!in_array($raw, ['0', '1'], true)) {
                $errors[] = $label . ' skrzynki: nieprawidłowa wartość.';
                continue;
            }
            $values[$field] = $raw === '1';
        }

        $recipient = trim((string)($data['digest_recipient'] ?? ''));
        if ($recipient !== '') {
            if (strlen($recipient) > 255 || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Odbiorca raportu kwarantanny: podaj poprawny adres e-mail albo zostaw puste (właściciel skrzynki).';
            } else {
                $values['digest_recipient'] = $recipient;
            }
        }

        $hour = trim((string)($data['digest_hour'] ?? ''));
        if ($hour !== '') {
            if (!preg_match('/^\d{1,2}$/', $hour) || (int)$hour > 23) {
                $errors[] = 'Godzina raportu kwarantanny: podaj godzinę 0-23 albo zostaw puste (harmonogram globalny).';
            } else {
                $values['digest_hour'] = (int)$hour;
            }
        }

        return [$values, $errors];
    }

    /** Store parsed overrides (parseOverrides()[0]) on the account. */
    public static function apply(Account $account, array $values): Account
    {
        return $account
            ->setSpamThreshold($values['spam_threshold'] ?? null)
            ->setQuarantineThreshold($values['quarantine_threshold'] ?? null)
            ->setScoringEnabled($values['scoring_enabled'] ?? null)
            ->setDigestEnabled($values['digest_enabled'] ?? null)
            ->setDigestRecipient($values['digest_recipient'] ?? null)
            ->setDigestHour($values['digest_hour'] ?? null);
    }

    private static function truthy($v): bool
    {
        return $v === true || in_array(strtolower(trim((string)$v)), ['1', 'true', 'yes', 'on'], true);
    }
}
