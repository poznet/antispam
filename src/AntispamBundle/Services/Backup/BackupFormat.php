<?php

namespace AntispamBundle\Services\Backup;

/**
 * Envelope of the configuration backup (`antispam:export` / `antispam:import`,
 * panel page "Kopia zapasowa"): one JSON document, optionally inside a ZIP.
 *
 *     {
 *       "format": "antispam-backup",
 *       "schema_version": 1,
 *       "app_version": "1.4.0" | null,
 *       "exported_at": "2026-10-28T12:00:00+00:00",
 *       "include_secrets": false,
 *       "secrets": null | {"cipher": "enc:v1", "key_check": "enc:v1:..."},
 *       "settings": {"config": {...}, "lists": {...}, "secrets": {...}},
 *       "rules": {"blacklist": [...], "whitelist": [...], "email_blacklist": [...], "email_whitelist": [...]},
 *       "dnsbl": [...],
 *       "accounts": [...],
 *       "users": [...]
 *     }
 *
 * See docs/backup.md for the field reference.
 */
final class BackupFormat
{
    public const FORMAT = 'antispam-backup';
    public const SCHEMA_VERSION = 1;
    /** Name of the JSON entry inside a .zip export. */
    public const ZIP_ENTRY = 'antispam-backup.json';
    /** Upper bound for the JSON document (also the unpacked ZIP entry). */
    public const MAX_BYTES = 20 * 1024 * 1024;

    public const SECTIONS = ['settings', 'rules', 'dnsbl', 'accounts', 'users'];

    /** Plain text encrypted with the instance key; decrypting it proves both instances share APP_SECRET. */
    public const KEY_CHECK_PLAINTEXT = 'antispam-backup-key-check';

    private function __construct()
    {
    }

    public static function encode(array $data): string
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . "\n";
    }

    /** ZIP archive (as a string) holding the JSON document and a short README. */
    public static function zip(string $json): string
    {
        if (!class_exists(\ZipArchive::class)) {
            throw new InvalidBackupException('The zip PHP extension is not installed - export to .json instead.');
        }
        $tmp = tempnam(sys_get_temp_dir(), 'asbak');
        try {
            $zip = new \ZipArchive();
            if ($zip->open($tmp, \ZipArchive::OVERWRITE) !== true) {
                throw new \RuntimeException('Cannot create the ZIP archive');
            }
            $zip->addFromString(self::ZIP_ENTRY, $json);
            $zip->addFromString('README.txt', "Antispam Pancernapanda configuration backup.\n"
                . "Restore: php bin/console antispam:import <this file> --dry-run, then without --dry-run.\n"
                . "See docs/backup.md.\n");
            $zip->close();

            return (string)file_get_contents($tmp);
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * Reads and validates a backup file (.json, or a .zip holding one).
     *
     * @throws InvalidBackupException
     */
    public static function readFile(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new InvalidBackupException('File not found or not readable: ' . $path);
        }
        $size = filesize($path);
        if ($size === false || $size > self::MAX_BYTES) {
            throw new InvalidBackupException(sprintf('File is larger than %d MB.', self::MAX_BYTES / 1048576));
        }
        $head = (string)file_get_contents($path, false, null, 0, 4);
        if ($head === "PK\x03\x04") {
            return self::decode(self::unzip($path));
        }

        return self::decode((string)file_get_contents($path));
    }

    private static function unzip(string $path): string
    {
        if (!class_exists(\ZipArchive::class)) {
            throw new InvalidBackupException('The zip PHP extension is not installed - unpack the archive and import the .json file.');
        }
        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::RDONLY) !== true) {
            throw new InvalidBackupException('Not a valid ZIP archive.');
        }
        try {
            $stat = $zip->statName(self::ZIP_ENTRY);
            if ($stat === false) {
                throw new InvalidBackupException('The ZIP archive does not contain ' . self::ZIP_ENTRY . '.');
            }
            // Reject before unpacking (zip bomb).
            if ($stat['size'] > self::MAX_BYTES) {
                throw new InvalidBackupException('The backup inside the ZIP archive is too large.');
            }
            $json = $zip->getFromName(self::ZIP_ENTRY, self::MAX_BYTES + 1);
            if ($json === false || strlen($json) > self::MAX_BYTES) {
                throw new InvalidBackupException('Cannot read ' . self::ZIP_ENTRY . ' from the ZIP archive.');
            }

            return $json;
        } finally {
            $zip->close();
        }
    }

    /**
     * Parses and validates the envelope and the shape of every section.
     *
     * @throws InvalidBackupException
     */
    public static function decode(string $json): array
    {
        if (strlen($json) > self::MAX_BYTES) {
            throw new InvalidBackupException('Backup is too large.');
        }
        try {
            $data = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidBackupException('Not a valid JSON document: ' . $e->getMessage());
        }
        if (!is_array($data) || ($data['format'] ?? null) !== self::FORMAT) {
            throw new InvalidBackupException('Not an antispam backup (missing "format": "' . self::FORMAT . '").');
        }
        $version = $data['schema_version'] ?? null;
        if (!is_int($version) || $version < 1) {
            throw new InvalidBackupException('Missing or invalid schema_version.');
        }
        if ($version > self::SCHEMA_VERSION) {
            throw new InvalidBackupException(sprintf(
                'Backup schema version %d is newer than this application supports (%d) - update the application first.',
                $version,
                self::SCHEMA_VERSION
            ));
        }

        foreach (['settings', 'rules'] as $section) {
            if (isset($data[$section]) && !self::isMap($data[$section])) {
                throw new InvalidBackupException('Section "' . $section . '" must be an object.');
            }
        }
        foreach (['dnsbl', 'accounts', 'users'] as $section) {
            if (isset($data[$section]) && !self::isListOfMaps($data[$section])) {
                throw new InvalidBackupException('Section "' . $section . '" must be a list of objects.');
            }
        }
        foreach ($data['rules'] ?? [] as $type => $rules) {
            if (!self::isListOfMaps($rules)) {
                throw new InvalidBackupException('Rule list "' . $type . '" must be a list of objects.');
            }
        }
        foreach (['config', 'lists', 'secrets'] as $part) {
            if (isset($data['settings'][$part]) && !self::isMap($data['settings'][$part])) {
                throw new InvalidBackupException('settings.' . $part . ' must be an object.');
            }
        }
        if (isset($data['secrets']) && !self::isMap($data['secrets'])) {
            throw new InvalidBackupException('"secrets" must be an object or null.');
        }

        return $data;
    }

    /** @return string[] sections to process; null/empty = all */
    public static function parseOnly(?string $only): array
    {
        if ($only === null || trim($only) === '') {
            return self::SECTIONS;
        }
        $sections = array_values(array_unique(array_filter(array_map('trim', explode(',', strtolower($only))))));
        $unknown = array_diff($sections, self::SECTIONS);
        if ($unknown) {
            throw new InvalidBackupException('Unknown section(s): ' . implode(', ', $unknown) . ' (allowed: ' . implode(', ', self::SECTIONS) . ').');
        }

        return $sections;
    }

    private static function isMap($value): bool
    {
        return is_array($value) && ($value === [] || !array_is_list($value));
    }

    private static function isListOfMaps($value): bool
    {
        if (!is_array($value) || !array_is_list($value)) {
            return false;
        }
        foreach ($value as $item) {
            if (!is_array($item) || ($item !== [] && array_is_list($item))) {
                return false;
            }
        }

        return true;
    }
}
