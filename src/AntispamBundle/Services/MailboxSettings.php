<?php

namespace AntispamBundle\Services;

/**
 * Effective (account override -> global) settings of one mailbox, built by
 * MailboxSettingsResolver. Immutable; `overrides` lists the fields the
 * account sets itself (field => value), empty for a mailbox that inherits
 * everything (and always for the legacy mailbox from the "E-mail" settings).
 */
final class MailboxSettings
{
    /**
     * @param string|null $digestRecipient where the quarantine digest goes (null = nowhere valid)
     * @param int|null    $digestHour      0-23: send the digest at the first run at/after this hour;
     *                                     null = whenever antispam:digest:send runs (global schedule)
     * @param array<string, mixed> $overrides
     */
    public function __construct(
        public readonly int $spamThreshold,
        public readonly int $quarantineThreshold,
        public readonly bool $scoringEnabled,
        public readonly bool $deleteSpam,
        public readonly bool $digestEnabled,
        public readonly ?string $digestRecipient,
        public readonly ?int $digestHour,
        public readonly array $overrides = [],
    ) {
    }

    public function hasOverrides(): bool
    {
        return $this->overrides !== [];
    }

    public function isOverridden(string $field): bool
    {
        return array_key_exists($field, $this->overrides);
    }
}
