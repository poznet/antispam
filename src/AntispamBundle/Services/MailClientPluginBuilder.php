<?php

namespace AntispamBundle\Services;

/**
 * Builds the downloads for mail clients other than Thunderbird
 * (see docs/outlook.md, docs/apple-mail.md):
 *
 *   - Outlook add-in: manifest XML with the server URL filled in, plus the
 *     task pane files it points to (served by the app itself);
 *   - Apple Mail: zip of the MailKit extension source with the server URL
 *     baked into ServerConfig.swift (it has to be built and signed in Xcode).
 */
class MailClientPluginBuilder
{
    /** Task pane files the Outlook manifest may reference, with content types. */
    const OUTLOOK_ASSETS = [
        'taskpane.html' => 'text/html; charset=UTF-8',
        'taskpane.js' => 'application/javascript; charset=UTF-8',
        'taskpane.css' => 'text/css; charset=UTF-8',
        'commands.html' => 'text/html; charset=UTF-8',
        'icons/icon-16.png' => 'image/png',
        'icons/icon-32.png' => 'image/png',
        'icons/icon-64.png' => 'image/png',
        'icons/icon-80.png' => 'image/png',
        'icons/icon-128.png' => 'image/png',
    ];

    const APPLE_SERVER_PLACEHOLDER = '__ANTISPAM_SERVER__';

    private string $resourceDir;

    public function __construct(?string $resourceDir = null)
    {
        $this->resourceDir = $resourceDir ?? dirname(__DIR__) . '/Resources';
    }

    /**
     * Office add-ins must be served over HTTPS (localhost is accepted for
     * development), otherwise Outlook refuses to install the manifest.
     */
    public static function isOutlookCompatible(string $base): bool
    {
        $parts = parse_url($base);
        if (empty($parts['scheme']) || empty($parts['host'])) {
            return false;
        }
        return $parts['scheme'] === 'https' || in_array($parts['host'], ['localhost', '127.0.0.1'], true);
    }

    /** Manifest XML for sideloading / central deployment. */
    public function outlookManifest(string $base): string
    {
        $base = rtrim($base, '/');
        $parts = parse_url($base);
        $origin = ($parts['scheme'] ?? 'https') . '://' . ($parts['host'] ?? '') . (isset($parts['port']) ? ':' . $parts['port'] : '');

        $xml = file_get_contents($this->resourceDir . '/outlook/manifest.xml');
        // Drop the template comment - it mentions the placeholders.
        $xml = preg_replace('/<!--.*?-->\s*/s', '', $xml, 1);
        return strtr($xml, [
            '{{BASE}}' => htmlspecialchars($base, ENT_XML1 | ENT_QUOTES, 'UTF-8'),
            '{{ORIGIN}}' => htmlspecialchars($origin, ENT_XML1 | ENT_QUOTES, 'UTF-8'),
        ]);
    }

    /** @return array{path:string, type:string}|null file of the task pane, null when not allowed */
    public function outlookAsset(string $file): ?array
    {
        if (!isset(self::OUTLOOK_ASSETS[$file])) {
            return null;
        }
        $path = $this->resourceDir . '/outlook/' . $file;
        return is_file($path) ? ['path' => $path, 'type' => self::OUTLOOK_ASSETS[$file]] : null;
    }

    /**
     * Zip of the Apple Mail extension source (Xcode / XcodeGen project) with
     * the server URL set. Returns the path of a temporary file.
     */
    public function appleMailSourceZip(string $base): string
    {
        $src = $this->resourceDir . '/applemail';
        $tmp = tempnam(sys_get_temp_dir(), 'amzip');

        $zip = new \ZipArchive();
        $zip->open($tmp, \ZipArchive::OVERWRITE);
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($src, \FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            $rel = str_replace('\\', '/', substr($file->getPathname(), strlen($src) + 1));
            $target = 'antispam-apple-mail/' . $rel;
            if ($rel === 'Shared/ServerConfig.swift') {
                $swift = file_get_contents($file->getPathname());
                $zip->addFromString($target, str_replace(self::APPLE_SERVER_PLACEHOLDER, addcslashes(rtrim($base, '/'), "\"\\"), $swift));
            } else {
                $zip->addFile($file->getPathname(), $target);
            }
        }
        $zip->close();
        return $tmp;
    }
}
