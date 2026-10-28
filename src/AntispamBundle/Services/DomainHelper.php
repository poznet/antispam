<?php

namespace AntispamBundle\Services;

/**
 * Small, dependency-free domain helpers shared by the impersonation and URL
 * analyzers: registrable-domain extraction (without a full Public Suffix
 * List), IDN decoding and a "skeleton" used to spot homoglyph lookalikes.
 */
class DomainHelper
{
    /**
     * Common multi-label public suffixes. Not a full PSL - just enough to keep
     * "firma.com.pl" from collapsing into "com.pl".
     */
    private static $multiLabelSuffixes = [
        'com.pl', 'net.pl', 'org.pl', 'info.pl', 'biz.pl', 'edu.pl', 'gov.pl',
        'waw.pl', 'krakow.pl', 'wroclaw.pl', 'poznan.pl', 'gda.pl', 'katowice.pl',
        'lodz.pl', 'szczecin.pl', 'lublin.pl', 'slask.pl', 'com.de',
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
        'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp',
        'com.br', 'com.cn', 'com.tr', 'com.ua', 'com.mx', 'com.ar', 'co.za',
        'co.in', 'co.il', 'co.kr', 'com.sg', 'com.hk', 'com.tw', 'com.ru',
    ];

    /**
     * Free-mail providers. Their domains are never auto-protected, because
     * providers legitimately operate sibling domains (interia.pl / interia.eu).
     */
    private static $freemail = [
        'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com',
        'msn.com', 'yahoo.com', 'icloud.com', 'me.com', 'aol.com', 'gmx.com',
        'gmx.de', 'gmx.net', 'proton.me', 'protonmail.com', 'zoho.com',
        'yandex.ru', 'mail.ru', 'wp.pl', 'o2.pl', 'onet.pl', 'onet.eu', 'op.pl',
        'interia.pl', 'interia.eu', 'interia.com', 'poczta.fm', 'gazeta.pl',
        'tlen.pl', 'vp.pl', 'buziaczek.pl', 'autograf.pl', 'int.pl', 'go2.pl',
        'spoko.pl', 'poczta.onet.pl',
    ];

    public static function normalize($domain)
    {
        $domain = strtolower(trim((string)$domain, " \t\r\n.[]"));
        if ($domain === '') {
            return '';
        }
        // Strip port / credentials if a URL authority slipped through.
        if (($p = strrpos($domain, '@')) !== false) {
            $domain = substr($domain, $p + 1);
        }
        $domain = preg_replace('/:\d+$/', '', $domain);
        return $domain;
    }

    public static function isIp($host)
    {
        return (bool)filter_var(trim((string)$host, '[]'), FILTER_VALIDATE_IP);
    }

    /**
     * "mail.sub.firma.com.pl" -> "firma.com.pl", "a.b.example.com" -> "example.com".
     */
    public static function registrable($domain)
    {
        $domain = self::normalize($domain);
        if ($domain === '' || self::isIp($domain)) {
            return $domain;
        }
        $labels = explode('.', $domain);
        $n = count($labels);
        if ($n <= 2) {
            return $domain;
        }
        $lastTwo = $labels[$n - 2] . '.' . $labels[$n - 1];
        if (in_array($lastTwo, self::$multiLabelSuffixes, true)) {
            return $labels[$n - 3] . '.' . $lastTwo;
        }
        return $lastTwo;
    }

    /**
     * The organisation label of a domain: "firma.com.pl" -> "firma".
     */
    public static function label($domain)
    {
        $reg = self::registrable($domain);
        $p = strpos($reg, '.');
        return $p === false ? $reg : substr($reg, 0, $p);
    }

    public static function suffix($domain)
    {
        $reg = self::registrable($domain);
        $p = strpos($reg, '.');
        return $p === false ? '' : substr($reg, $p + 1);
    }

    public static function isFreemail($domain)
    {
        return in_array(self::registrable($domain), self::$freemail, true);
    }

    /**
     * Punycode (ASCII) form of a domain: pure-ASCII input is returned as is,
     * Unicode needs the intl extension ('' when it cannot be converted).
     */
    public static function toAscii($domain)
    {
        $domain = self::normalize($domain);
        if ($domain === '' || !preg_match('/[^\x00-\x7F]/', $domain)) {
            return $domain;
        }
        if (!function_exists('idn_to_ascii')) {
            return '';
        }
        $variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 0;
        $ascii = @idn_to_ascii($domain, 0, $variant);
        return $ascii ? strtolower($ascii) : '';
    }

    /**
     * Decode punycode labels ("xn--...") to Unicode when the intl extension is
     * available; otherwise return the input unchanged.
     */
    public static function toUnicode($domain)
    {
        $domain = self::normalize($domain);
        if (strpos($domain, 'xn--') === false || !function_exists('idn_to_utf8')) {
            return $domain;
        }
        $variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 0;
        $decoded = @idn_to_utf8($domain, 0, $variant);
        return $decoded ? $decoded : $domain;
    }

    /**
     * Collapse visually confusable characters so "pozycj0ner", "pozycjoner"
     * and the Cyrillic "роzусjоnеr" share one skeleton.
     */
    public static function skeleton($label)
    {
        $s = mb_strtolower(self::toUnicode($label), 'UTF-8');
        // 1. Cyrillic / Greek letters that render like Latin ones
        $s = strtr($s, [
            'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y',
            'х' => 'x', 'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'һ' => 'h', 'ԁ' => 'd',
            'ӏ' => 'l', 'ԝ' => 'w', 'ο' => 'o', 'α' => 'a', 'ε' => 'e', 'ι' => 'i',
            'κ' => 'k', 'ν' => 'v', 'τ' => 't', 'υ' => 'u', 'ρ' => 'p',
            'ı' => 'i', 'ɩ' => 'i', 'ɑ' => 'a', 'ɡ' => 'g', 'ł' => 'l',
        ]);
        // 2. Latin diacritics: é -> e, ą -> a, ü -> u
        if (function_exists('transliterator_transliterate')) {
            $t = @transliterator_transliterate('Latin-ASCII', $s);
            if (is_string($t)) {
                $s = $t;
            }
        } else {
            $s = strtr($s, ['ą' => 'a', 'ć' => 'c', 'ę' => 'e', 'ń' => 'n', 'ó' => 'o', 'ś' => 's', 'ź' => 'z', 'ż' => 'z']);
        }
        // 3. Digit and multi-character lookalikes
        return strtr($s, [
            '0' => 'o', '1' => 'l', '3' => 'e', '5' => 's', '$' => 's',
            'rn' => 'm', 'vv' => 'w', 'cl' => 'd', 'i' => 'l',
        ]);
    }

    /**
     * Unicode-aware edit distance with transpositions (levenshtein() is
     * byte-based and counts a swap as two edits).
     */
    public static function distance($a, $b)
    {
        $a = preg_split('//u', (string)$a, -1, PREG_SPLIT_NO_EMPTY);
        $b = preg_split('//u', (string)$b, -1, PREG_SPLIT_NO_EMPTY);
        $la = count($a);
        $lb = count($b);
        if ($la === 0) return $lb;
        if ($lb === 0) return $la;
        // Optimal string alignment: a transposition ("frima") costs 1, like a typo.
        $d = [];
        for ($i = 0; $i <= $la; $i++) { $d[$i] = [$i]; }
        for ($j = 0; $j <= $lb; $j++) { $d[0][$j] = $j; }
        for ($i = 1; $i <= $la; $i++) {
            for ($j = 1; $j <= $lb; $j++) {
                $cost = $a[$i - 1] === $b[$j - 1] ? 0 : 1;
                $d[$i][$j] = min($d[$i - 1][$j] + 1, $d[$i][$j - 1] + 1, $d[$i - 1][$j - 1] + $cost);
                if ($i > 1 && $j > 1 && $a[$i - 1] === $b[$j - 2] && $a[$i - 2] === $b[$j - 1]) {
                    $d[$i][$j] = min($d[$i][$j], $d[$i - 2][$j - 2] + 1);
                }
            }
        }
        return $d[$la][$lb];
    }
}
