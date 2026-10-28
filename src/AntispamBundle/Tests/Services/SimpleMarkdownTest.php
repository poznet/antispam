<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\SimpleMarkdown;
use PHPUnit\Framework\TestCase;

class SimpleMarkdownTest extends TestCase
{
    private function render(string $md): string
    {
        return (new SimpleMarkdown())->render($md);
    }

    public function testHeadingsListsAndInline()
    {
        $html = $this->render("# Changelog\n\n## [2.0.0] - 2026-10-28\n\n### Added\n- `AppVersion` and **bold**\n- *italic* item\n  continued\n  - nested\n- back\n\nA paragraph\non two lines.\n");

        $this->assertStringContainsString('<h1>Changelog</h1>', $html);
        $this->assertStringContainsString('<h2>[2.0.0] - 2026-10-28</h2>', $html);
        $this->assertStringContainsString('<h3>Added</h3>', $html);
        $this->assertStringContainsString('<code>AppVersion</code> and <strong>bold</strong>', $html);
        $this->assertStringContainsString("<em>italic</em> item\n continued", $html);
        $this->assertStringContainsString("<ul><li>\nnested\n</li></ul>", $html);
        $this->assertStringContainsString('<p>A paragraph on two lines.</p>', $html);
        $this->assertSame(substr_count($html, '<ul>'), substr_count($html, '</ul>'));
        $this->assertSame(substr_count($html, '<li>'), substr_count($html, '</li>'));
    }

    public function testEverythingIsEscaped()
    {
        $html = $this->render("## <img src=x onerror=alert(1)>\n- <script>alert(1)</script>\n- `<b>code</b>`\n\n<div onclick=\"x\">raw</div>\n\n```\n<?php echo 1; ?>\n```\n");

        $this->assertStringNotContainsString('<img', $html);
        $this->assertStringNotContainsString('<script', $html);
        $this->assertStringNotContainsString('<div', $html);
        $this->assertStringNotContainsString('<b>', $html);
        $this->assertStringContainsString('&lt;img src=x onerror=alert(1)&gt;', $html);
        $this->assertStringContainsString('<code>&lt;b&gt;code&lt;/b&gt;</code>', $html);
        $this->assertStringContainsString('<pre><code>&lt;?php echo 1; ?&gt;</code></pre>', $html);
    }

    public function testOnlySafeLinks()
    {
        $html = $this->render("[ok](https://keepachangelog.com/en/1.1.0/) [rel](/changelog) [bad](javascript:alert(1)) [q](https://x.test/?a=\"b)\n\n[2.0.0]: https://example.com/compare\n");

        $this->assertStringContainsString('<a href="https://keepachangelog.com/en/1.1.0/" rel="noopener noreferrer" target="_blank">ok</a>', $html);
        $this->assertStringContainsString('<a href="/changelog">rel</a>', $html);
        $this->assertStringNotContainsString('javascript:', $html);
        $this->assertStringContainsString('bad', $html);
        $this->assertStringContainsString('href="https://x.test/?a=&quot;b"', $html);
        $this->assertStringNotContainsString('example.com/compare', $html);
    }

    public function testRendersTheRealChangelog()
    {
        $html = $this->render((string) file_get_contents(dirname(__DIR__, 4) . '/CHANGELOG.md'));
        $this->assertStringContainsString('<h2>[Unreleased]</h2>', $html);
        $this->assertMatchesRegularExpression('~<h2>\[' . preg_quote(\AntispamBundle\AppVersion::VERSION, '~') . '\] - \d{4}-\d{2}-\d{2} \(current\)</h2>~', $html);
        $this->assertSame(substr_count($html, '<ul>'), substr_count($html, '</ul>'));
    }
}
