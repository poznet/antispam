<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\PatternMatcher;
use PHPUnit\Framework\TestCase;

class PatternMatcherTest extends TestCase
{
    public function testWildcardEscapesRegexDelimiterAndMetacharacters()
    {
        $this->assertTrue(PatternMatcher::match('*~promo.pl', 'news~promo.pl', PatternMatcher::WILDCARD));
        $this->assertTrue(PatternMatcher::match('*.evil.pl', 'mx.evil.pl', PatternMatcher::WILDCARD));
        $this->assertFalse(PatternMatcher::match('*.evil.pl', 'mxXevil.pl', PatternMatcher::WILDCARD));
        $this->assertTrue(PatternMatcher::match('a#b?.pl', 'a#bc.pl', PatternMatcher::WILDCARD));
    }

    public function testCatastrophicRegexDoesNotMatchInsteadOfHanging()
    {
        $limit = ini_get('pcre.backtrack_limit');
        $started = microtime(true);
        $ini = ini_get('error_log');
        ini_set('error_log', '/dev/null');
        try {
            $this->assertFalse(PatternMatcher::match('(a+)+$', str_repeat('a', 40) . '!', PatternMatcher::REGEX));
        } finally {
            ini_set('error_log', (string)$ini);
        }
        $this->assertLessThan(2.0, microtime(true) - $started);
        $this->assertSame($limit, ini_get('pcre.backtrack_limit'), 'limit restored');
    }

    public function testValidate()
    {
        $this->assertSame('', PatternMatcher::validate('^.*@evil\.pl$', PatternMatcher::REGEX));
        $this->assertNotSame('', PatternMatcher::validate('(', PatternMatcher::REGEX));
        $this->assertNotSame('', PatternMatcher::validate('(a+)+$', PatternMatcher::REGEX));
        $this->assertSame('', PatternMatcher::validate('(', PatternMatcher::WILDCARD));
    }
}
