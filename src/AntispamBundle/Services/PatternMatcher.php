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

    public static function match($pattern, $value, $type = self::EXACT)
    {
        if ($pattern === null || $pattern === '' || $value === null || $value === '') {
            return false;
        }

        $value = strtolower((string)$value);
        $pattern = (string)$pattern;

        switch ($type) {
            case self::REGEX:
                $regex = '~' . str_replace('~', '\~', $pattern) . '~i';
                $ok = @preg_match($regex, $value);
                if ($ok === false) {
                    error_log('[antispam] invalid regex pattern: ' . $pattern);
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
                case '|': case '/':
                    $out .= '\\' . $c;
                    break;
                default:
                    $out .= $c;
            }
        }
        return $out;
    }
}
