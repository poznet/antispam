<?php

namespace AntispamBundle\Services;

use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Builds the Thunderbird .xpi and keeps an uploaded "store" build
 * (see docs/plugin-distribution.md, docs/thunderbird.md).
 *
 *   - instance build: config.json with this server's URL, the server origin in
 *     the host permissions and, over https, an update_url pointing at
 *     /plugin/thunderbird/updates.json (self-hosted automatic updates);
 *   - generic build: the source as is, no config.json and no update_url - one
 *     package for every instance (the user enters the server address on first
 *     run). This is the file to submit to addons.thunderbird.net (ATN);
 *   - uploaded build: a generic package the admin uploaded in the panel (e.g.
 *     the file ATN serves after review); /plugin/download prefers it.
 *
 * Builds are reproducible: entries sorted, fixed timestamps and permissions,
 * so the same source + server URL give a byte-identical file (with the same
 * zlib). No dependencies besides ext-zip, so bin/build-thunderbird-xpi can use
 * it without booting Symfony (CI).
 */
class ThunderbirdPluginBuilder
{
    const ADDON_ID = 'antispam@pancernapanda.pl';
    const UPDATES_PATH = '/plugin/thunderbird/updates.json';
    /** 2026-01-01 00:00:00 UTC - timestamp of every zip entry (reproducible builds). */
    const FIXED_MTIME = 1767225600;
    /** Largest accepted upload (the package is ~100 KiB). */
    const UPLOAD_MAX_BYTES = 5 * 1024 * 1024;

    const UPLOAD_FILE = 'thunderbird-uploaded.xpi';
    const UPLOAD_META = 'thunderbird-uploaded.json';

    private string $sourceDir;
    private string $storageDir;

    public function __construct(
        ?string $sourceDir = null,
        #[Autowire('%kernel.project_dir%/var/data/plugin')] ?string $storageDir = null,
    ) {
        $this->sourceDir = $sourceDir ?? dirname(__DIR__) . '/Resources/thunderbird';
        $this->storageDir = $storageDir ?? dirname(__DIR__, 3) . '/var/data/plugin';
    }

    /** Version of the bundled source (manifest.json). */
    public function version(): string
    {
        return (string)($this->sourceManifest()['version'] ?? '');
    }

    /**
     * Manifest of a build. $server = null: generic build (unchanged source
     * manifest); otherwise the server origin is added to the host permissions
     * and, for an https server, update_url is set.
     */
    public function manifest(?string $server): array
    {
        $manifest = $this->sourceManifest();
        if ($server === null) {
            return $manifest;
        }
        $parts = parse_url($server);
        if (!empty($parts['scheme']) && !empty($parts['host'])) {
            // Match patterns cannot carry a port; the host alone covers every port.
            $manifest['permissions'][] = $parts['scheme'] . '://' . $parts['host'] . '/*';
            if ($parts['scheme'] === 'http') {
                // The proxy may redirect http:// to https:// - without this the
                // redirected request is blocked as cross-origin.
                $manifest['permissions'][] = 'https://' . $parts['host'] . '/*';
            }
            $manifest['permissions'] = array_values(array_unique($manifest['permissions']));
            // Thunderbird fetches update manifests over https only.
            if ($parts['scheme'] === 'https') {
                $manifest['browser_specific_settings']['gecko']['update_url'] = rtrim($server, '/') . self::UPDATES_PATH;
            }
        }
        return $manifest;
    }

    /**
     * Writes the .xpi to $target. $server = null builds the generic package
     * (no config.json), otherwise the URL is baked into config.json.
     */
    public function build(?string $server, string $target): void
    {
        if (!class_exists(\ZipArchive::class)) {
            throw new \RuntimeException('PHP zip extension is required to build the plugin');
        }
        $server = $server === null ? null : rtrim($server, '/');

        $files = [];
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->sourceDir, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($this->sourceDir) + 1));
            if ($rel === 'config.json' || $rel === 'manifest.json' || $this->isJunk($rel)) {
                continue;
            }
            $files[$rel] = file_get_contents($file->getPathname());
        }
        $files['manifest.json'] = json_encode($this->manifest($server), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
        if ($server !== null) {
            // Pre-configured server URL, so the user never has to type it.
            $files['config.json'] = json_encode(['server' => $server], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        }
        // manifest.json first (convention), the rest in byte order.
        uksort($files, fn ($a, $b) => [$a !== 'manifest.json', $a] <=> [$b !== 'manifest.json', $b]);

        @unlink($target);
        $zip = new \ZipArchive();
        if ($zip->open($target, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
            throw new \RuntimeException('Cannot create ' . $target);
        }
        foreach ($files as $name => $content) {
            $zip->addFromString($name, $content);
            $zip->setCompressionName($name, \ZipArchive::CM_DEFLATE);
            $zip->setMtimeName($name, self::FIXED_MTIME);
            $zip->setExternalAttributesName($name, \ZipArchive::OPSYS_UNIX, 0100644 << 16);
        }
        if (!$zip->close()) {
            throw new \RuntimeException('Cannot write ' . $target);
        }
    }

    /** Builds into a temporary file and returns its path (caller deletes it). */
    public function buildTemp(?string $server): string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'tbxpi');
        if ($tmp === false) {
            throw new \RuntimeException('Cannot create a temporary file');
        }
        try {
            $this->build($server, $tmp);
        } catch (\Throwable $e) {
            @unlink($tmp);
            throw $e;
        }
        return $tmp;
    }

    /**
     * Update manifest for the instance builds (update_url). Thunderbird
     * installs the version listed here when it is higher than the installed one.
     * The link is https (required without update_hash); no hash is published
     * because the package is built per request.
     */
    public function updatesManifest(string $downloadUrl): array
    {
        $gecko = $this->sourceManifest()['browser_specific_settings']['gecko'] ?? [];
        $update = ['version' => $this->version(), 'update_link' => $downloadUrl];
        if (!empty($gecko['strict_min_version'])) {
            $update['applications'] = ['gecko' => ['strict_min_version' => $gecko['strict_min_version']]];
        }
        return ['addons' => [self::ADDON_ID => ['updates' => [$update]]]];
    }

    // --- uploaded build -----------------------------------------------------

    /**
     * Reads and checks an .xpi: a zip with manifest.json of this add-on (id),
     * no baked-in server URL (a package of another instance would send the
     * users' mail there). signed = carries a Mozilla signature (META-INF).
     *
     * @return array{id:string, version:string, signed:bool}
     * @throws \InvalidArgumentException with a message for the admin
     */
    public function inspect(string $path): array
    {
        if (!is_file($path) || filesize($path) === 0) {
            throw new \InvalidArgumentException('Pusty plik.');
        }
        if (filesize($path) > self::UPLOAD_MAX_BYTES) {
            throw new \InvalidArgumentException('Plik jest za duży (maks. ' . (self::UPLOAD_MAX_BYTES >> 20) . ' MiB).');
        }
        $zip = new \ZipArchive();
        if ($zip->open($path, \ZipArchive::RDONLY) !== true) {
            throw new \InvalidArgumentException('To nie jest plik .xpi (archiwum zip).');
        }
        try {
            $manifest = json_decode((string)$zip->getFromName('manifest.json'), true);
            if (!is_array($manifest)) {
                throw new \InvalidArgumentException('W archiwum brakuje poprawnego manifest.json.');
            }
            $gecko = $manifest['browser_specific_settings']['gecko'] ?? $manifest['applications']['gecko'] ?? [];
            $id = (string)($gecko['id'] ?? '');
            if ($id !== self::ADDON_ID) {
                throw new \InvalidArgumentException('To inny dodatek (id „' . $id . '”, oczekiwano „' . self::ADDON_ID . '”).');
            }
            $version = (string)($manifest['version'] ?? '');
            if (!preg_match('/^\d+(\.\d+){0,3}$/', $version)) {
                throw new \InvalidArgumentException('Nieprawidłowa wersja w manifest.json.');
            }
            $config = $zip->getFromName('config.json');
            if ($config !== false && trim((string)(json_decode($config, true)['server'] ?? '')) !== '') {
                throw new \InvalidArgumentException('To wersja z wpisanym adresem serwera (config.json) - wgraj wersję ogólną (bez adresu).');
            }
            $signed = $zip->locateName('META-INF/mozilla.rsa') !== false || $zip->locateName('META-INF/cose.sig') !== false;
        } finally {
            $zip->close();
        }
        return ['id' => $id, 'version' => $version, 'signed' => $signed];
    }

    /**
     * Stores an uploaded generic package. Its version must equal the bundled
     * plugin version, so the download never goes back to older code.
     *
     * @return array uploadedBuild() of the stored file
     * @throws \InvalidArgumentException
     */
    public function storeUpload(string $tmpPath, string $originalName = ''): array
    {
        $info = $this->inspect($tmpPath);
        if ($info['version'] !== $this->version()) {
            throw new \InvalidArgumentException('Wersja pliku (' . $info['version'] . ') różni się od wersji wtyczki na serwerze (' . $this->version() . ').');
        }
        if (!is_dir($this->storageDir) && !@mkdir($this->storageDir, 0775, true) && !is_dir($this->storageDir)) {
            throw new \RuntimeException('Cannot create ' . $this->storageDir);
        }
        $target = $this->storageDir . '/' . self::UPLOAD_FILE;
        $part = $target . '.part';
        if (!@copy($tmpPath, $part) || !@rename($part, $target)) {
            @unlink($part);
            throw new \RuntimeException('Cannot store the uploaded plugin');
        }
        $meta = $info + [
            'sha256' => hash_file('sha256', $target),
            'size' => filesize($target),
            'name' => mb_substr(basename($originalName), 0, 120),
            'uploaded_at' => date(DATE_ATOM),
        ];
        file_put_contents($this->storageDir . '/' . self::UPLOAD_META, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        return $this->uploadedBuild();
    }

    /**
     * The uploaded package, or null. `current` = same version as the bundled
     * plugin (only then is it served by /plugin/download).
     *
     * @return array{path:string, id:string, version:string, signed:bool, sha256:string, size:int, name:string, uploaded_at:string, current:bool}|null
     */
    public function uploadedBuild(): ?array
    {
        $path = $this->storageDir . '/' . self::UPLOAD_FILE;
        $meta = json_decode((string)@file_get_contents($this->storageDir . '/' . self::UPLOAD_META), true);
        if (!is_file($path) || !is_array($meta) || empty($meta['version'])) {
            return null;
        }
        return [
            'path' => $path,
            'id' => (string)($meta['id'] ?? ''),
            'version' => (string)$meta['version'],
            'signed' => !empty($meta['signed']),
            'sha256' => (string)($meta['sha256'] ?? ''),
            'size' => (int)($meta['size'] ?? 0),
            'name' => (string)($meta['name'] ?? ''),
            'uploaded_at' => (string)($meta['uploaded_at'] ?? ''),
            'current' => $meta['version'] === $this->version(),
        ];
    }

    public function removeUpload(): void
    {
        @unlink($this->storageDir . '/' . self::UPLOAD_FILE);
        @unlink($this->storageDir . '/' . self::UPLOAD_META);
    }

    private function sourceManifest(): array
    {
        $manifest = json_decode((string)file_get_contents($this->sourceDir . '/manifest.json'), true);
        if (!is_array($manifest)) {
            throw new \RuntimeException('Invalid Thunderbird manifest.json');
        }
        return $manifest;
    }

    /** Editor / OS leftovers never go into the package. */
    private function isJunk(string $rel): bool
    {
        $base = basename($rel);
        return $base === '.DS_Store' || $base === 'Thumbs.db' || str_ends_with($base, '~') || str_starts_with($base, '.');
    }
}
