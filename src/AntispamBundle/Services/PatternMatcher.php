<?php

namespace AntispamBundle\Services;

/**
 * Matches a value against a pattern of type exact | wildcard | regex.
 *
 * Wildcard uses shell globs (* and ?). Regex uses PHP PCRE without delimiters
 * (we add ~...~i). Bad regex patterns never match and are logged to the error
 * log so a malformed rule can't crash the whole scan.
 */
class PatternMatcher
{
    const EXACT = 'exact';
    const WILDCARD = 'wildcard';
    const REGEX = 'regex';
    /** pcre.backtrack_limit while matching admin regexes (PHP default: 1000000). */
    const BACKTRACK_LIMIT = 100000;

    public static function match($pattern, $value, $type = self::EXACT)
    {
        if ($pattern === null || $pattern === '' || $value === null || $value === '') {
            return false;
        }

        $value = strtolower((string)$value);
        $pattern = (string)$pattern;

        switch ($type) {
            case self::REGEX:
                $ok = self::boundedMatch(self::regexOf($pattern), $value);
                if ($ok === false) {
                    error_log('[antispam] invalid or too expensive regex pattern: ' . $pattern);
                    return false;
                }
                return $ok === 1;

            case self::WILDCARD:
                $regex = '~^' . self::globToRegex(strtolower($pattern)) . '$~i';
                return @preg_match($regex, $value) === 1;

            case self::EXACT:
            default:
                return strtolower($pattern) === $value;
        }
    }

    /**
     * Error message for a pattern that can never work ('' when it is fine),
     * for the rule forms: an invalid regex, or one so expensive that it hits
     * the backtracking limit on a plain address.
     */
    public static function validate($pattern, $type)
    {
        if ($type !== self::REGEX) {
            return '';
        }
        $regex = self::regexOf((string)$pattern);
        if (@preg_match($regex, '') === false) {
            return 'Nieprawidłowe wyrażenie regularne.';
        }
        if (self::boundedMatch($regex, str_repeat('a', 64) . '@' . str_repeat('b', 64) . '.example.com!') === false) {
            return 'Wyrażenie regularne jest zbyt kosztowne (zagnieżdżone powtórzenia).';
        }
        return '';
    }

    /**
     * @param object[] $rules  each rule must expose getPatternType() and a value getter via $valueGetter
     */
    public static function findMatching(array $rules, $value, $valueGetter)
    {
        foreach ($rules as $rule) {
            $pattern = $rule->{$valueGetter}();
            $type = method_exists($rule, 'getPatternType') ? $rule->getPatternType() : self::EXACT;
            if (self::match($pattern, $value, $type)) {
                return $rule;
            }
        }
        return null;
    }

    private static function regexOf($pattern)
    {
        return '~' . str_replace('~', '\\~', (string)$pattern) . '~i';
    }

    /**
     * preg_match with a low backtracking limit, so an admin regex such as
     * (a+)+$ cannot stall the scan on a crafted address (ReDoS); a pattern
     * that hits the limit simply does not match.
     *
     * @return int|false
     */
    private static function boundedMatch($regex, $value)
    {
        $previous = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', (string)self::BACKTRACK_LIMIT);
        try {
            $ok = @preg_match($regex, $value);
            return ($ok === false || preg_last_error() !== PREG_NO_ERROR) ? false : $ok;
        } finally {
            ini_set('pcre.backtrack_limit', (string)$previous);
        }
    }

    private static function globToRegex($glob)
    {
        $out = '';
        $len = strlen($glob);
        for ($i = 0; $i < $len; $i++) {
            $c = $glob[$i];
            switch ($c) {
                case '*': $out .= '.*'; break;
                case '?': $out .= '.'; break;
                case '.': case '\\': case '+': case '(': case ')':
                case '[': case ']': case '{': case '}': case '^': case '$':
                case '|': case '/': case '~': case '#':
                    $out .= '\\' . $c;
                    break;
                default:
                    $out .= $c;
            }
        }
        return $out;
    }
}
