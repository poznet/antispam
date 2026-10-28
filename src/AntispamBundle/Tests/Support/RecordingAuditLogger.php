<?php

namespace AntispamBundle\Tests\Support;

use AntispamBundle\Services\AuditLogger;

/**
 * AuditLogger that keeps the entries in memory instead of writing them -
 * for controller tests. quarantine() goes through the real mapping (action
 * key, details) and ends in log(); resolving a mailbox from the quarantine
 * key finds nothing here (no database), so tests pass it or expect null.
 */
class RecordingAuditLogger extends AuditLogger
{
    /** @var array<int, array<string, mixed>> */
    public array $entries = [];

    public function __construct()
    {
    }

    public function log(
        string $action,
        ?string $targetType = null,
        int|string|null $targetId = null,
        ?string $label = null,
        ?string $mailbox = null,
        array $details = [],
        ?string $actor = null,
        ?string $actorType = null,
        ?string $role = null,
    ): void {
        $this->entries[] = [
            'action' => $action,
            'targetType' => $targetType,
            'targetId' => $targetId,
            'label' => $label,
            'mailbox' => $mailbox,
            'details' => self::sanitize($details),
            'actor' => $actor,
            'actorType' => $actorType,
            'role' => $role,
        ];
    }

    public function mailboxForKey(string $key): ?string
    {
        return null;
    }

    /** @return string[] */
    public function actions(): array
    {
        return array_column($this->entries, 'action');
    }

    public function last(): array
    {
        return $this->entries[count($this->entries) - 1] ?? [];
    }
}
