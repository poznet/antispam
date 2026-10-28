<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Services\ThunderbirdPluginBuilder;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

#[RequiresPhpExtension('zip')]
class ThunderbirdPluginBuilderTest extends TestCase
{
    private array $cleanup = [];
    private string $storage;

    protected function setUp(): void
    {
        $this->storage = sys_get_temp_dir() . '/tbstore-' . bin2hex(random_bytes(4));
        $this->cleanup[] = $this->storage;
    }

    protected function tearDown(): void
    {
        foreach ($this->cleanup as $path) {
            if (is_dir($path)) {
                foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST) as $f) {
                    $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
                }
                rmdir($path);
            } else {
                @unlink($path);
            }
        }
    }

    private function builder(?string $source = null): ThunderbirdPluginBuilder
    {
        return new ThunderbirdPluginBuilder($source, $this->storage);
    }

    private function tmp(string $suffix = '.xpi'): string
    {
        $path = sys_get_temp_dir() . '/tbtest-' . bin2hex(random_bytes(4)) . $suffix;
        $this->cleanup[] = $path;
        return $path;
    }

    /** @return array<string,string> entry name => content */
    private function entries(string $xpi): array
    {
        $zip = new \ZipArchive();
        $this->assertTrue($zip->open($xpi));
        $out = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            $out[$name] = $zip->getFromIndex($i);
        }
        $zip->close();
        return $out;
    }

    /** A zip with the given entries (for upload validation). */
    private function makeXpi(array $entries): string
    {
        $path = $this->tmp();
        $zip = new \ZipArchive();
        $zip->open($path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
        foreach ($entries as $name => $content) {
            $zip->addFromString($name, is_array($content) ? json_encode($content) : $content);
        }
        $zip->close();
        return $path;
    }

    private function manifestOf(string $id = ThunderbirdPluginBuilder::ADDON_ID, string $version = PluginApiController::PLUGIN_VERSION): array
    {
        return ['manifest_version' => 2, 'name' => 'x', 'version' => $version, 'browser_specific_settings' => ['gecko' => ['id' => $id]]];
    }

    public function testVersionMatchesPluginVersion()
    {
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $this->builder()->version());
    }

    public function testGenericBuildHasNoServerAndAValidManifest()
    {
        $xpi = $this->tmp();
        $this->builder()->build(null, $xpi);
        $entries = $this->entries($xpi);

        $this->assertArrayNotHasKey('config.json', $entries, 'generic build carries no server URL');
        $this->assertSame('manifest.json', array_key_first($entries));
        $manifest = json_decode($entries['manifest.json'], true);
        $this->assertIsArray($manifest);
        $this->assertSame(2, $manifest['manifest_version']);
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $manifest['version']);
        $this->assertSame(ThunderbirdPluginBuilder::ADDON_ID, $manifest['browser_specific_settings']['gecko']['id']);
        $this->assertArrayNotHasKey('update_url', $manifest['browser_specific_settings']['gecko'], 'ATN rejects update_url in listed add-ons');
        $this->assertNotContains('https://antispam.example.pl/*', $manifest['permissions']);
        $this->assertContains('*://*/*', $manifest['optional_permissions'], 'user-entered servers need the optional host permission');

        // Every file the manifest / pages reference is in the package.
        foreach (array_merge($manifest['background']['scripts'], array_values($manifest['icons']), [$manifest['options_ui']['page']]) as $file) {
            $this->assertArrayHasKey($file, $entries, $file);
        }
        preg_match_all('/<script src="([^"]+)"/', $entries['options.html'], $m);
        foreach ($m[1] as $file) {
            $this->assertArrayHasKey($file, $entries, $file);
        }
    }

    public function testInstanceBuildBakesServerAndUpdateUrl()
    {
        $xpi = $this->tmp();
        $this->builder()->build('https://antispam.example.pl/', $xpi);
        $entries = $this->entries($xpi);

        $this->assertSame(['server' => 'https://antispam.example.pl'], json_decode($entries['config.json'], true));
        $manifest = json_decode($entries['manifest.json'], true);
        $this->assertContains('https://antispam.example.pl/*', $manifest['permissions']);
        $this->assertSame('https://antispam.example.pl/plugin/thunderbird/updates.json', $manifest['browser_specific_settings']['gecko']['update_url']);
    }

    public function testHttpInstanceBuildHasNoUpdateUrl()
    {
        $manifest = $this->builder()->manifest('http://10.0.0.5:8080');
        $this->assertArrayNotHasKey('update_url', $manifest['browser_specific_settings']['gecko'], 'Thunderbird reads update manifests over https only');
        $this->assertContains('http://10.0.0.5/*', $manifest['permissions']);
        $this->assertContains('https://10.0.0.5/*', $manifest['permissions']);
    }

    public function testBuildIsReproducible()
    {
        // A copy of the source with other file timestamps gives the same bytes.
        $src = dirname(__DIR__, 2) . '/Resources/thunderbird';
        $copy = sys_get_temp_dir() . '/tbsrc-' . bin2hex(random_bytes(4));
        $this->cleanup[] = $copy;
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($src, \FilesystemIterator::SKIP_DOTS)) as $f) {
            $target = $copy . substr($f->getPathname(), strlen($src));
            @mkdir(dirname($target), 0775, true);
            copy($f->getPathname(), $target);
            touch($target, 1000000000);
        }
        file_put_contents($copy . '/.DS_Store', 'junk');

        $a = $this->tmp();
        $b = $this->tmp();
        $this->builder()->build(null, $a);
        $this->builder($copy)->build(null, $b);
        $this->assertSame(hash_file('sha256', $a), hash_file('sha256', $b));
        $this->assertArrayNotHasKey('.DS_Store', $this->entries($b));
    }

    public function testUpdatesManifestFormat()
    {
        $data = $this->builder()->updatesManifest('https://antispam.example.pl/plugin/download?build=instance&v=1');
        $updates = $data['addons'][ThunderbirdPluginBuilder::ADDON_ID]['updates'];
        $this->assertCount(1, $updates);
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $updates[0]['version']);
        $this->assertSame('https://antispam.example.pl/plugin/download?build=instance&v=1', $updates[0]['update_link']);
        $this->assertSame('115.0', $updates[0]['applications']['gecko']['strict_min_version']);
    }

    public function testUploadOfGenericBuildIsStored()
    {
        $xpi = $this->tmp();
        $b = $this->builder();
        $b->build(null, $xpi);
        $this->assertNull($b->uploadedBuild());

        $info = $b->storeUpload($xpi, '../evil/antispam.xpi');
        $this->assertSame(PluginApiController::PLUGIN_VERSION, $info['version']);
        $this->assertFalse($info['signed']);
        $this->assertTrue($info['current']);
        $this->assertSame('antispam.xpi', $info['name']);
        $this->assertSame(hash_file('sha256', $xpi), $info['sha256']);
        $this->assertFileEquals($xpi, $info['path']);

        $b->removeUpload();
        $this->assertNull($b->uploadedBuild());
    }

    public function testSignedPackageIsDetected()
    {
        $xpi = $this->makeXpi(['manifest.json' => $this->manifestOf(), 'META-INF/cose.sig' => 'sig', 'META-INF/mozilla.rsa' => 'rsa']);
        $this->assertTrue($this->builder()->inspect($xpi)['signed']);
    }

    public static function badUploads(): array
    {
        return [
            'not a zip' => ['plain text', 'archiwum zip'],
            'no manifest' => [['background.js' => 'x'], 'manifest.json'],
            'other add-on' => [['manifest.json' => ['version' => '1.0', 'browser_specific_settings' => ['gecko' => ['id' => 'evil@example.com']]]], 'inny dodatek'],
            'other version' => [['manifest.json' => 'VERSION:9.9.9'], 'różni się'],
            'instance build of some server' => [['manifest.json' => 'OK', 'config.json' => ['server' => 'https://evil.example']], 'config.json'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('badUploads')]
    public function testBadUploadsAreRejected(string|array $content, string $message)
    {
        if (is_string($content)) {
            $path = $this->tmp();
            file_put_contents($path, $content);
        } else {
            foreach ($content as $name => $v) {
                if ($v === 'OK') {
                    $content[$name] = $this->manifestOf();
                } elseif (is_string($v) && str_starts_with($v, 'VERSION:')) {
                    $content[$name] = $this->manifestOf(version: substr($v, 8));
                }
            }
            $path = $this->makeXpi($content);
        }
        try {
            $this->builder()->storeUpload($path);
            $this->fail('upload should be rejected');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString($message, $e->getMessage());
        }
        $this->assertNull($this->builder()->uploadedBuild());
    }

    public function testUploadOfOlderVersionIsNotCurrent()
    {
        // Stored when it matched, then the server got a newer plugin.
        $b = $this->builder();
        $b->storeUpload($this->makeXpi(['manifest.json' => $this->manifestOf()]));
        $meta = $this->storage . '/' . ThunderbirdPluginBuilder::UPLOAD_META;
        $data = json_decode(file_get_contents($meta), true);
        $data['version'] = '0.9';
        file_put_contents($meta, json_encode($data));
        $this->assertFalse($b->uploadedBuild()['current']);
    }
}
