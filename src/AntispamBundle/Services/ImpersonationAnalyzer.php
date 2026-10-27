<?php

namespace AntispamBundle\Services;

/**
 * Business Email Compromise / impersonation heuristics (inspired by Barracuda
 * Impersonation Protection):
 *
 *   - VIP display-name spoofing: "Jan Kowalski <jan.kowalski1984@gmail.com>"
 *     where Jan Kowalski is a protected person who never mails from there
 *   - e-mail address embedded in the display name that differs from the real
 *     sender ("ceo@firma.pl" <attacker@evil.com>)
 *   - lookalike / cousin domains of protected domains: typos (firrna.pl),
 *     homoglyphs (f1rma.pl, Cyrillic letters, punycode), other TLDs
 *     (firma.com vs firma.pl), affixes (firma-pl.com, secure-firma.com) and
 *     subdomain tricks (firma.pl.evil.com)
 *   - internal-domain spoofing: From claims a protected domain but SPF or
 *     DMARC explicitly failed
 *
 * Pure logic, no I/O: the same rules are mirrored in the Maildir agent.
 */
class ImpersonationAnalyzer
{
    const DEFAULT_SCORES = [
        'vip' => 8,
        'lookalike' => 6,
        'embedded' => 3,
        'internal' => 6,
    ];

    /**
     * Parse VIP definitions, one per line: "Jan Kowalski" or
     * "Jan Kowalski <jan@firma.pl>, jan.k@firma.pl".
     *
     * @return array list of ['name' => normalized name, 'label' => original, 'emails' => [..]]
     */
    public static function parseVips($lines)
    {
        if (!is_array($lines)) {
            $lines = preg_split('/\r?\n/', (string)$lines);
        }
        $vips = [];
        foreach ($lines as $line) {
            $line = trim((string)$line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            preg_match_all('/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i', $line, $m);
            $emails = array_map('strtolower', $m[0]);
            $name = trim(preg_replace('/[<>(),]|[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i', ' ', $line));
            $norm = self::normalizeName($name);
            if ($norm === '' || strpos($norm, ' ') === false) {
                // Single-word names ("Anna") would match far too much mail.
                continue;
            }
            $vips[] = ['name' => $norm, 'label' => $name, 'emails' => $emails];
        }
        return $vips;
    }

    public static function parseDomains($lines)
    {
        if (!is_array($lines)) {
            $lines = preg_split('/[\s,;]+/', (string)$lines);
        }
        $out = [];
        foreach ($lines as $d) {
            $d = DomainHelper::normalize($d);
            if ($d !== '' && strpos($d, '.') !== false && $d[0] !== '#') {
                $out[$d] = true;
            }
        }
        return array_keys($out);
    }

    /**
     * @param array $msg ['from_name' => string, 'from_email' => string, 'auth_results' => string]
     * @param array $protectedDomains list of domains
     * @param array $vips output of parseVips()
     * @param array $scores overrides for DEFAULT_SCORES
     *
     * @return array ['score' => int, 'reasons' => [...]]
     */
    public function analyze(array $msg, array $protectedDomains, array $vips, array $scores = [])
    {
        $scores = array_merge(self::DEFAULT_SCORES, array_filter($scores, 'is_numeric'));
        $fromEmail = strtolower(trim((string)($msg['from_email'] ?? '')));
        $fromName = self::decodeName((string)($msg['from_name'] ?? ''));
        $fromDomain = DomainHelper::normalize(substr(strrchr($fromEmail, '@') ?: '', 1));
        $auth = strtolower((string)($msg['auth_results'] ?? ''));

        $score = 0;
        $reasons = [];
        if ($fromEmail === '' || $fromDomain === '') {
            return ['score' => 0, 'reasons' => []];
        }

        $protectedRegs = [];
        foreach ($protectedDomains as $d) {
            $protectedRegs[DomainHelper::registrable($d)] = $d;
        }
        $fromReg = DomainHelper::registrable($fromDomain);
        $fromIsProtected = isset($protectedRegs[$fromReg]);

        // 1. VIP display-name spoofing
        $normName = self::normalizeName($fromName);
        if ($normName !== '') {
            foreach ($vips as $vip) {
                if (!self::nameMatches($normName, $vip['name'])) {
                    continue;
                }
                $legit = $vip['emails']
                    ? in_array($fromEmail, $vip['emails'], true)
                    : $fromIsProtected;
                if (!$legit) {
                    $score += (int)$scores['vip'];
                    $reasons[] = ['rule' => 'impersonation_vip:' . $vip['label'], 'score' => (int)$scores['vip'], 'sender' => $fromEmail];
                }
                break;
            }
        }

        // 2. A different address embedded in the display name
        if (preg_match('/[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})/i', $fromName, $m)
            && strtolower($m[0]) !== $fromEmail) {
            $embeddedReg = DomainHelper::registrable($m[1]);
            if (isset($protectedRegs[$embeddedReg]) && !$fromIsProtected) {
                $score += (int)$scores['vip'];
                $reasons[] = ['rule' => 'impersonation_display_address:' . strtolower($m[0]), 'score' => (int)$scores['vip']];
            } else {
                $score += (int)$scores['embedded'];
                $reasons[] = ['rule' => 'display_name_embedded_address', 'score' => (int)$scores['embedded']];
            }
        }

        // 3. Lookalike / cousin domain
        if (!$fromIsProtected) {
            foreach ($protectedRegs as $reg => $orig) {
                $why = self::lookalikeReason($fromDomain, $reg);
                if ($why !== null) {
                    $score += (int)$scores['lookalike'];
                    $reasons[] = ['rule' => 'lookalike_domain:' . $fromDomain . '~' . $reg, 'score' => (int)$scores['lookalike'], 'match' => $why];
                    break;
                }
            }
        }

        // 4. Own (protected) domain with failed authentication
        if ($fromIsProtected && (preg_match('/\bspf=(fail|softfail)\b/', $auth) || preg_match('/\bdmarc=fail\b/', $auth))) {
            $score += (int)$scores['internal'];
            $reasons[] = ['rule' => 'internal_domain_spoof:' . $fromDomain, 'score' => (int)$scores['internal']];
        }

        return ['score' => $score, 'reasons' => $reasons];
    }

    /**
     * Why $domain looks like the protected registrable domain $protectedReg,
     * or null when it doesn't.
     */
    public static function lookalikeReason($domain, $protectedReg)
    {
        $domain = DomainHelper::normalize($domain);
        $reg = DomainHelper::registrable($domain);
        if ($reg === $protectedReg || $reg === '') {
            return null;
        }
        $pLabel = DomainHelper::label($protectedReg);
        $dLabel = DomainHelper::label(DomainHelper::toUnicode($reg));
        if (mb_strlen($pLabel, 'UTF-8') < 4) {
            return null; // "wp", "o2", "abc": too short to compare meaningfully
        }

        // firma.pl.evil.com
        if (strpos($domain . '.', $protectedReg . '.') !== false) {
            return 'subdomain';
        }
        // Same name, other TLD: firma.com vs firma.pl
        if ($dLabel === $pLabel) {
            return 'tld';
        }
        // Homoglyphs / punycode: f1rma, firrna, Cyrillic "а"
        if (DomainHelper::skeleton($dLabel) === DomainHelper::skeleton($pLabel)) {
            return 'homoglyph';
        }
        // Affixes: firma-pl, secure-firma, firma24
        if (preg_match('/(^|[-0-9])' . preg_quote($pLabel, '/') . '($|[-0-9])/', $dLabel)) {
            return 'affix';
        }
        // Typos: firnna, frima
        $len = mb_strlen($pLabel, 'UTF-8');
        if ($len >= 5) {
            $max = $len >= 10 ? 2 : 1;
            if (DomainHelper::distance($dLabel, $pLabel) <= $max) {
                return 'typo';
            }
        }
        return null;
    }

    public static function normalizeName($name)
    {
        $name = mb_strtolower(trim((string)$name, " \t\"'"), 'UTF-8');
        if ($name === '') {
            return '';
        }
        if (function_exists('transliterator_transliterate')) {
            $t = @transliterator_transliterate('Any-Latin; Latin-ASCII', $name);
            if ($t !== false && $t !== null) {
                $name = $t;
            }
        } else {
            $name = strtr($name, ['ą' => 'a', 'ć' => 'c', 'ę' => 'e', 'ł' => 'l', 'ń' => 'n', 'ó' => 'o', 'ś' => 's', 'ź' => 'z', 'ż' => 'z']);
        }
        $name = preg_replace('/[^a-z0-9@. ]+/', ' ', $name);
        return trim(preg_replace('/\s+/', ' ', $name));
    }

    /**
     * Display name matches a VIP when it contains the VIP's words in either
     * order: "Jan Kowalski", "Kowalski Jan", "Jan Kowalski (CEO)".
     */
    private static function nameMatches($normName, $vipName)
    {
        if (strpos(' ' . $normName . ' ', ' ' . $vipName . ' ') !== false) {
            return true;
        }
        $words = explode(' ', $normName);
        foreach (explode(' ', $vipName) as $w) {
            if (!in_array($w, $words, true)) {
                return false;
            }
        }
        return true;
    }

    private static function decodeName($name)
    {
        if (strpos($name, '=?') !== false && function_exists('mb_decode_mimeheader')) {
            $name = mb_decode_mimeheader($name);
        }
        return trim($name, " \t\"'");
    }
}
