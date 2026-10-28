<?php

namespace AntispamBundle\Services\Backup;

/** What an import did (or, with --dry-run, would do), per section. */
class ImportReport
{
    public const ACTIONS = ['created', 'updated', 'unchanged', 'deleted', 'skipped'];
    private const MAX_WARNINGS = 500;

    /** @var array<string, array<string, int>> section => action => count */
    private array $counts = [];
    /** @var string[] */
    private array $warnings = [];
    private int $droppedWarnings = 0;

    public function __construct(
        public readonly string $mode,
        public readonly bool $dryRun,
        /** @var string[] */
        public readonly array $sections,
        public readonly array $meta = [],
    ) {
        foreach ($sections as $section) {
            $this->counts[$section] = array_fill_keys(self::ACTIONS, 0);
        }
    }

    public function count(string $section, string $action, int $n = 1): void
    {
        $this->counts[$section] ??= array_fill_keys(self::ACTIONS, 0);
        $this->counts[$section][$action] += $n;
    }

    public function warn(string $message): void
    {
        if (count($this->warnings) >= self::MAX_WARNINGS) {
            $this->droppedWarnings++;
            return;
        }
        $this->warnings[] = $message;
    }

    /** @return array<string, array<string, int>> */
    public function getCounts(): array
    {
        return $this->counts;
    }

    /** @return string[] */
    public function getWarnings(): array
    {
        return $this->droppedWarnings > 0
            ? array_merge($this->warnings, [sprintf('... and %d more warning(s).', $this->droppedWarnings)])
            : $this->warnings;
    }

    public function total(string $action): int
    {
        return array_sum(array_column($this->counts, $action));
    }

    /** True when the import changes (or would change) anything. */
    public function hasChanges(): bool
    {
        return $this->total('created') + $this->total('updated') + $this->total('deleted') > 0;
    }
}
