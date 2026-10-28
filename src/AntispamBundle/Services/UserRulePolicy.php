<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;

/**
 * What an end user (/my/rules) may put on the white/blacklists of their own
 * mailboxes. Stricter than the admin forms:
 *
 *  - exact and wildcard only - no regex (cost, ReDoS, and hard to get right);
 *  - a wildcard must still end in a literal domain: a blacklist at least in a
 *    TLD (`*.ru`), a whitelist in a registrable-looking domain
 *    (`*.firma.pl`, `*@firma.pl`) - so `*` / `*@*` cannot switch the filter
 *    off for a mailbox;
 *  - a plain character set (no spaces / control characters / quotes).
 */
final class UserRulePolicy
{
    /** list key => [entity class, value field, value kind, is blacklist] */
    public const LISTS = [
        'whitelist' => [Whitelist::class, 'host', 'domain', false],
        'email_whitelist' => [EmailWhitelist::class, 'whitelistemail', 'email', false],
        'blacklist' => [Blacklist::class, 'host', 'domain', true],
        'email_blacklist' => [EmailBlacklist::class, 'blacklistemail', 'email', true],
    ];

    public const LABELS = [
        'whitelist' => 'Zaufane domeny',
        'email_whitelist' => 'Zaufani nadawcy',
        'blacklist' => 'Blokowane domeny',
        'email_blacklist' => 'Blokowani nadawcy',
    ];

    public const TYPES = [PatternMatcher::EXACT, PatternMatcher::WILDCARD];

    public const MAX_LENGTH = 255;

    public static function normalize(string $list, string $value): string
    {
        $value = strtolower(trim($value));
        if ((self::LISTS[$list][2] ?? null) === 'domain') {
            $value = ltrim($value, '@');
        }
        return $value;
    }

    /** Polish error message, or null when the rule is acceptable. $value must be normalize()d. */
    public static function validate(string $list, string $value, string $type): ?string
    {
        if (!isset(self::LISTS[$list])) {
            return 'Nieznana lista.';
        }
        if ($type === PatternMatcher::REGEX) {
            return 'Wyrażenia regularne może dodawać tylko administrator - użyj wzorca dokładnego lub wildcard (*).';
        }
        if (!in_array($type, self::TYPES, true)) {
            return 'Nieznany typ wzorca.';
        }
        [, , $kind, $isBlacklist] = self::LISTS[$list];
        if ($value === '') {
            return 'Podaj adres lub domenę.';
        }
        if (strlen($value) > self::MAX_LENGTH) {
            return 'Wartość jest za długa.';
        }

        $charset = $kind === 'domain' ? '/^[a-z0-9.\-*?]+$/' : '/^[a-z0-9.!#$%&\'+\/=^_`{|}~\-@*?]+$/';
        if (preg_match($charset, $value) !== 1) {
            return $kind === 'domain'
                ? 'Domena może zawierać tylko litery a-z, cyfry, kropki i myślniki (domeny z polskimi znakami wpisz w zapisie punycode, xn--...).'
                : 'Adres zawiera niedozwolone znaki.';
        }

        $hasWildcard = strpbrk($value, '*?') !== false;
        if ($type === PatternMatcher::EXACT) {
            if ($hasWildcard) {
                return 'Znaki * i ? działają tylko we wzorcu wildcard.';
            }
            if ($kind === 'email' && preg_match('/^[^@]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/', $value) !== 1) {
                return 'Podaj pełny adres e-mail, np. jan@firma.pl.';
            }
            if ($kind === 'domain' && preg_match('/^[a-z0-9-]+(\.[a-z0-9-]+)+$/', $value) !== 1) {
                return 'Podaj domenę, np. firma.pl.';
            }
            return null;
        }

        // Wildcard: the part after the last * / ? must be a literal domain ending.
        $tail = (string)substr($value, max((int)strrpos($value, '*'), (int)strrpos($value, '?')) + ($hasWildcard ? 1 : 0));
        if ($kind === 'email' && strpos($value, '@') === false) {
            return 'Wzorzec adresu musi zawierać @, np. *@firma.pl.';
        }
        $ok = $isBlacklist
            ? preg_match('/\.[a-z0-9-]{2,}$/', $tail) === 1
            : preg_match('/[a-z0-9-]+\.[a-z0-9-]{2,}$/', $tail) === 1;
        if (!$ok) {
            return $isBlacklist
                ? 'Wzorzec musi kończyć się domeną, np. *.example.com, *@example.com lub *.ru.'
                : 'Wzorzec zaufanych nadawców musi kończyć się konkretną domeną, np. *@firma.pl lub *.firma.pl.';
        }
        return null;
    }
}
