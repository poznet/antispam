<?php

namespace AntispamBundle\Services;

/**
 * Attachment policy (inspired by Barracuda attachment filtering). Works on
 * file names and raw bytes only - no daemon, no API key - so it also runs on
 * shared hosting through the Maildir agent.
 *
 *   - blocked file types by extension (exe, js, iso, lnk, ...)
 *   - double extensions ("faktura.pdf.exe") and Unicode bidi tricks
 *     ("faktura\u{202E}fdp.exe" renders as "fakturaexe.pdf")
 *   - executable content (MZ / ELF header) disguised under another extension
 *   - blocked file types hidden inside ZIP archives
 *   - VBA macros in Office documents (OOXML vbaProject.bin, legacy OLE)
 *   - active content in PDFs (/JavaScript, /Launch)
 *   - password-protected ZIP archives and encrypted Office documents, which
 *     are opaque to every scanner
 */
class AttachmentPolicyAnalyzer
{
    const DEFAULT_BLOCKED = [
        'exe', 'scr', 'pif', 'com', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse',
        'wsf', 'wsh', 'hta', 'msi', 'msp', 'cpl', 'jar', 'ps1', 'psm1', 'lnk',
        'iso', 'img', 'vhd', 'vhdx', 'reg', 'scf', 'chm', 'dll', 'appx',
        'msix', 'xll', 'url', 'inf', 'sct', 'gadget',
    ];

    const DEFAULT_SCORES = [
        'blocked_score' => 15,
        'double_ext_score' => 8,
        'mismatch_score' => 10,
        'macro_score' => 6,
        'encrypted_score' => 5,
    ];

    const MAX_INSPECT = 26214400; // 25 MiB per attachment

    private static $executableExt = ['exe', 'dll', 'scr', 'com', 'sys', 'cpl', 'ocx', 'drv', 'efi', 'pif', 'bin', 'elf', 'so', 'run', 'out', 'appimage'];

    private static $decoyExt = [
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'odt',
        'ods', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tif', 'tiff', 'mp3', 'mp4',
        'avi', 'mov', 'zip', 'rar', '7z', 'htm', 'html', 'csv', 'xml', 'eml',
    ];

    public static function parseExtensions($list)
    {
        if (!is_array($list)) {
            $list = preg_split('/[\s,;]+/', (string)$list);
        }
        $out = [];
        foreach ($list as $e) {
            $e = strtolower(trim((string)$e, " \t\r\n.*"));
            if ($e !== '' && preg_match('/^[a-z0-9]{1,16}$/', $e)) {
                $out[$e] = true;
            }
        }
        return array_keys($out);
    }

    /**
     * @param array $attachments list of ['filename' => string, 'data' => string]
     * @param array $config ['blocked_extensions' => string[], ...scores]
     *
     * @return array ['score' => int, 'reasons' => [...]]
     */
    public function analyze(array $attachments, array $config = [])
    {
        $config = array_merge(self::DEFAULT_SCORES, ['blocked_extensions' => self::DEFAULT_BLOCKED], $config);
        $blocked = self::parseExtensions($config['blocked_extensions']);

        $score = 0;
        $reasons = [];
        $fired = [];
        $add = function ($key, $rule, $points, $filename) use (&$score, &$reasons, &$fired) {
            if (isset($fired[$key]) || (int)$points <= 0) {
                return;
            }
            $fired[$key] = true;
            $score += (int)$points;
            $reasons[] = ['rule' => $rule, 'score' => (int)$points, 'filename' => $filename];
        };

        foreach ($attachments as $att) {
            $rawName = (string)($att['filename'] ?? '');
            $name = self::normalizeFilename($rawName);
            $data = (string)($att['data'] ?? '');
            if (strlen($data) > self::MAX_INSPECT) {
                $data = substr($data, 0, self::MAX_INSPECT);
            }
            $ext = self::extensionOf($name);

            if ($ext !== '' && in_array($ext, $blocked, true)) {
                $add('blocked', 'attachment_blocked:' . $ext, $config['blocked_score'], $name);
            }

            if (self::hasBidiOverride($rawName . $name)) {
                $add('double', 'attachment_bidi_filename', $config['double_ext_score'], $name);
            } elseif (self::isDoubleExtension($name, $blocked)) {
                $add('double', 'attachment_double_extension', $config['double_ext_score'], $name);
            }

            $magic = self::executableMagic($data);
            if ($magic !== '' && !in_array($ext, self::$executableExt, true)) {
                $add('mismatch', 'attachment_disguised_executable:' . $magic, $config['mismatch_score'], $name);
            }

            if (strncmp($data, "PK\x03\x04", 4) === 0) {
                $zip = self::inspectZip($data);
                foreach ($zip['names'] as $inner) {
                    $innerExt = self::extensionOf(self::normalizeFilename($inner));
                    if ($innerExt !== '' && in_array($innerExt, $blocked, true)) {
                        $add('archive', 'attachment_archive_blocked:' . $innerExt, $config['blocked_score'], $name . '/' . basename($inner));
                        break;
                    }
                }
                if ($zip['macro']) {
                    $add('macro', 'attachment_office_macro', $config['macro_score'], $name);
                }
                if ($zip['encrypted']) {
                    $add('encrypted', 'attachment_encrypted_archive', $config['encrypted_score'], $name);
                }
            } elseif (strncmp($data, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8) === 0) {
                // Legacy OLE2 compound file (doc/xls/ppt/msi). Directory entry
                // names are UTF-16LE.
                if (strpos($data, self::utf16('_VBA_PROJECT')) !== false || strpos($data, self::utf16('Macros')) !== false) {
                    $add('macro', 'attachment_office_macro', $config['macro_score'], $name);
                }
                if (strpos($data, self::utf16('EncryptedPackage')) !== false) {
                    $add('encrypted', 'attachment_encrypted_office', $config['encrypted_score'], $name);
                }
            } elseif (strncmp($data, '%PDF', 4) === 0) {
                if (preg_match('~/(JavaScript|JS|Launch)\b~', $data, $m)) {
                    $add('macro', 'attachment_pdf_active:' . strtolower($m[1]), $config['macro_score'], $name);
                }
            }
        }

        return ['score' => $score, 'reasons' => $reasons];
    }

    /**
     * Decode RFC 2047 / RFC 2231 encoded names and strip the trailing dots and
     * spaces Windows ignores ("invoice.exe. " opens as "invoice.exe").
     */
    public static function normalizeFilename($name)
    {
        $name = trim((string)$name, " \t\r\n\"");
        if (preg_match("/^[\\w\\-]+'[\\w\\-]*'(.+)$/", $name, $m)) {
            $name = rawurldecode($m[1]);
        }
        if (strpos($name, '=?') !== false && function_exists('mb_decode_mimeheader')) {
            $name = mb_decode_mimeheader($name);
        }
        $name = str_replace('\\', '/', $name);
        $name = rtrim($name, " .\t");
        return mb_strtolower($name, 'UTF-8');
    }

    public static function extensionOf($name)
    {
        $base = basename(str_replace('\\', '/', (string)$name));
        $p = strrpos($base, '.');
        if ($p === false || $p === 0) {
            return '';
        }
        return strtolower(trim(substr($base, $p + 1)));
    }

    private static function isDoubleExtension($name, array $blocked)
    {
        $base = basename($name);
        $ext = self::extensionOf($base);
        if ($ext === '' || (!in_array($ext, $blocked, true) && !in_array($ext, self::$executableExt, true))) {
            return false;
        }
        $stem = substr($base, 0, -strlen($ext) - 1);
        // "report.pdf      .exe" - padding to push the real extension out of view
        if (preg_match('/\s{3,}$/', $stem)) {
            return true;
        }
        $inner = self::extensionOf(rtrim($stem));
        return $inner !== '' && in_array($inner, self::$decoyExt, true);
    }

    private static function hasBidiOverride($name)
    {
        // U+202A..U+202E, U+2066..U+2069 (embedding / override / isolate)
        return (bool)preg_match('/\x{202A}|\x{202B}|\x{202C}|\x{202D}|\x{202E}|\x{2066}|\x{2067}|\x{2068}|\x{2069}/u', (string)$name);
    }

    private static function executableMagic($data)
    {
        if (strncmp($data, 'MZ', 2) === 0 && strlen($data) > 64) {
            // Confirm the PE header so a text file starting with "MZ" isn't flagged.
            $off = unpack('V', substr($data, 60, 4))[1];
            if ($off > 0 && $off < strlen($data) - 4 && substr($data, $off, 4) === "PE\0\0") {
                return 'pe';
            }
        }
        if (strncmp($data, "\x7FELF", 4) === 0) {
            return 'elf';
        }
        return '';
    }

    /**
     * Walk ZIP local file headers without extracting anything.
     *
     * @return array ['names' => string[], 'macro' => bool, 'encrypted' => bool]
     */
    public static function inspectZip($data)
    {
        $out = ['names' => [], 'macro' => false, 'encrypted' => false];
        $len = strlen($data);
        $pos = 0;
        $isOoxml = false;
        $encryptedEntries = 0;
        for ($i = 0; $i < 2000; $i++) {
            $pos = strpos($data, "PK\x03\x04", $pos);
            if ($pos === false || $pos + 30 > $len) {
                break;
            }
            $h = unpack('vversion/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnamelen/vextralen', substr($data, $pos + 4, 26));
            $name = substr($data, $pos + 30, $h['namelen']);
            if ($name !== '') {
                $out['names'][] = $name;
                if ($name === '[Content_Types].xml') {
                    $isOoxml = true;
                }
                if (preg_match('~(^|/)vbaProject\.bin$~i', $name)) {
                    $out['macro'] = true;
                }
            }
            if ($h['flags'] & 1) {
                $encryptedEntries++;
            }
            $pos += 30 + $h['namelen'] + $h['extralen'];
        }
        $out['encrypted'] = $encryptedEntries > 0 && !$isOoxml;
        return $out;
    }

    private static function utf16($ascii)
    {
        return implode("\0", str_split($ascii)) . "\0";
    }
}
