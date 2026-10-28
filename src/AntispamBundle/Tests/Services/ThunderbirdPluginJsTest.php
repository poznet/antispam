<?php

namespace AntispamBundle\Tests\Services;

use PHPUnit\Framework\TestCase;

/**
 * Thunderbird plugin JavaScript: syntax of every file and the first-run flow
 * of a build without a server URL (tests/js/thunderbird-first-run.mjs, mocked
 * WebExtension APIs). Skipped when node is not installed (e.g. the Docker image).
 */
class ThunderbirdPluginJsTest extends TestCase
{
    private static ?string $node = null;

    private function node(): string
    {
        if (self::$node === null) {
            $found = trim((string)@shell_exec('command -v node 2>/dev/null'));
            self::$node = $found !== '' && is_executable($found) ? $found : '';
        }
        if (self::$node === '') {
            $this->markTestSkipped('node is not installed');
        }
        return self::$node;
    }

    public function testPluginScriptsParse()
    {
        $node = $this->node();
        foreach (glob(dirname(__DIR__, 2) . '/Resources/thunderbird/*.js') as $file) {
            exec(escapeshellarg($node) . ' --check ' . escapeshellarg($file) . ' 2>&1', $out, $code);
            $this->assertSame(0, $code, basename($file) . ': ' . implode("\n", $out));
        }
    }

    public function testFirstRunFlow()
    {
        $node = $this->node();
        exec(escapeshellarg($node) . ' ' . escapeshellarg(dirname(__DIR__, 4) . '/tests/js/thunderbird-first-run.mjs') . ' 2>&1', $out, $code);
        $this->assertSame(0, $code, implode("\n", $out));
        $this->assertStringContainsString('all checks passed', implode("\n", $out));
    }
}
