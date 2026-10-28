<?php

namespace AntispamBundle;

/**
 * Single source of truth for the application version (semver, see CHANGELOG.md
 * and docs/deployment.md "Releasing"). The git commit the image was built from
 * is written to REVISION in the project root by the Dockerfile (build arg
 * GIT_COMMIT); outside Docker the file is usually missing and commit() is null.
 *
 * Exposed as the container parameter `antispam.version`, the Twig global
 * `antispam_version` (this object), `server_version` in /api/plugin/status and
 * `bin/console --version`.
 */
final class AppVersion
{
    public const VERSION = '2.0.0';
    public const REVISION_FILE = 'REVISION';

    private ?string $commit = null;
    private bool $commitLoaded = false;

    public function __construct(private string $projectDir)
    {
    }

    public function version(): string
    {
        return self::VERSION;
    }

    /** Short commit hash of the build, or null when unknown. */
    public function commit(): ?string
    {
        if (!$this->commitLoaded) {
            $this->commitLoaded = true;
            $this->commit = self::readRevision($this->projectDir . '/' . self::REVISION_FILE);
        }

        return $this->commit;
    }

    /** "2.0.0" or "2.0.0 (abc1234)". */
    public function full(): string
    {
        $commit = $this->commit();

        return $commit === null ? self::VERSION : sprintf('%s (%s)', self::VERSION, $commit);
    }

    public function __toString(): string
    {
        return $this->full();
    }

    /**
     * Reads a REVISION file defensively: only a hex hash (shortened to 7
     * chars) is accepted, "unknown", empty or garbage content yields null.
     */
    public static function readRevision(string $file): ?string
    {
        if (!is_file($file) || !is_readable($file)) {
            return null;
        }
        $value = strtolower(trim((string) @file_get_contents($file, false, null, 0, 200)));

        return preg_match('/^[0-9a-f]{7,40}$/', $value) ? substr($value, 0, 7) : null;
    }
}
