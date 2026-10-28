<?php

namespace AntispamBundle\Services;

/**
 * Tiny, safe Markdown -> HTML renderer for CHANGELOG.md ("Co nowego").
 *
 * Supports: ATX headings (# .. ######), "-" / "*" bullet lists (two-space
 * nesting), fenced code blocks, paragraphs, horizontal rules, and inline
 * `code`, **bold**, *italic* and [text](url) links (http/https or relative
 * only). Raw HTML is never passed through: every piece of text is escaped
 * before the inline markup is applied, so the output contains only the tags
 * this class emits. Link reference definitions ("[x]: url") are dropped.
 */
final class SimpleMarkdown
{
    public function render(string $markdown): string
    {
        $lines = preg_split('/\R/', str_replace("\t", '    ', $markdown));
        $html = [];
        $paragraph = [];
        $listDepth = 0;
        $inCode = false;
        $code = [];

        $flushParagraph = function () use (&$paragraph, &$html) {
            if ($paragraph) {
                $html[] = '<p>' . $this->inline(implode(' ', $paragraph)) . '</p>';
                $paragraph = [];
            }
        };
        $closeLists = function (int $to = 0) use (&$listDepth, &$html) {
            while ($listDepth > $to) {
                $html[] = '</li></ul>';
                $listDepth--;
            }
        };

        foreach ($lines as $line) {
            if ($inCode) {
                if (preg_match('/^\s*```/', $line)) {
                    $html[] = '<pre><code>' . self::e(implode("\n", $code)) . '</code></pre>';
                    $inCode = false;
                    $code = [];
                } else {
                    $code[] = $line;
                }
                continue;
            }
            if (preg_match('/^\s*```/', $line)) {
                $flushParagraph();
                $closeLists();
                $inCode = true;
                continue;
            }
            if (trim($line) === '') {
                $flushParagraph();
                continue;
            }
            if (preg_match('/^\s{0,3}\[[^\]]+\]:\s*\S+\s*$/', $line)) {
                continue; // link reference definition
            }
            if (preg_match('/^(#{1,6})\s+(.*?)\s*#*\s*$/', $line, $m)) {
                $flushParagraph();
                $closeLists();
                $level = strlen($m[1]);
                $html[] = sprintf('<h%d>%s</h%d>', $level, $this->inline($m[2]), $level);
                continue;
            }
            if (preg_match('/^\s*([-*_])(\s*\1){2,}\s*$/', $line)) {
                $flushParagraph();
                $closeLists();
                $html[] = '<hr>';
                continue;
            }
            if (preg_match('/^( *)[-*+]\s+(.*)$/', $line, $m)) {
                $flushParagraph();
                $depth = min(intdiv(strlen($m[1]), 2) + 1, $listDepth + 1);
                if ($depth > $listDepth) {
                    $html[] = '<ul><li>';
                    $listDepth = $depth;
                } else {
                    $closeLists($depth);
                    $html[] = '</li><li>';
                }
                $html[] = $this->inline($m[2]);
                continue;
            }
            if ($listDepth > 0 && preg_match('/^\s+\S/', $line)) {
                $html[] = ' ' . $this->inline(trim($line)); // continuation of a list item
                continue;
            }
            $closeLists();
            $paragraph[] = trim($line);
        }

        if ($inCode) {
            $html[] = '<pre><code>' . self::e(implode("\n", $code)) . '</code></pre>';
        }
        $flushParagraph();
        $closeLists();

        return implode("\n", $html);
    }

    /** Escapes the text, then applies `code`, links, **bold** and *italic*. */
    private function inline(string $text): string
    {
        $parts = preg_split('/(`[^`]+`)/', $text, -1, PREG_SPLIT_DELIM_CAPTURE);
        $out = '';
        foreach ($parts as $i => $part) {
            if ($i % 2 === 1) {
                $out .= '<code>' . self::e(substr($part, 1, -1)) . '</code>';
                continue;
            }
            $s = self::e($part);
            $s = preg_replace_callback('/\[([^\]]+)\]\(([^)\s]+)\)/', static function ($m) {
                $url = html_entity_decode($m[2], ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if (!preg_match('~^(https?://|/|#)~i', $url)) {
                    return $m[1];
                }
                $external = stripos($url, 'http') === 0 ? ' rel="noopener noreferrer" target="_blank"' : '';

                return '<a href="' . self::e($url) . '"' . $external . '>' . $m[1] . '</a>';
            }, $s);
            $s = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $s);
            $s = preg_replace('/(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])/', '<em>$1</em>', $s);
            $out .= $s;
        }

        return $out;
    }

    private static function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
