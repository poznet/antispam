<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\UserRulePolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class UserRulePolicyTest extends TestCase
{
    public static function accepted(): array
    {
        return [
            ['email_whitelist', 'jan@firma.pl', 'exact'],
            ['email_whitelist', '*@firma.pl', 'wildcard'],
            ['email_whitelist', 'faktury-?@firma.com.pl', 'wildcard'],
            ['whitelist', 'firma.pl', 'exact'],
            ['whitelist', '*.firma.pl', 'wildcard'],
            ['blacklist', 'spam.example', 'exact'],
            ['blacklist', '*.ru', 'wildcard'],
            ['email_blacklist', '*@*.ru', 'wildcard'],
            ['email_blacklist', 'promo+x@sklep.pl', 'exact'],
        ];
    }

    #[DataProvider('accepted')]
    public function testAccepted(string $list, string $value, string $type)
    {
        $this->assertNull(UserRulePolicy::validate($list, UserRulePolicy::normalize($list, $value), $type));
    }

    public static function rejected(): array
    {
        return [
            'regex' => ['email_whitelist', '.*@firma\.pl', 'regex'],
            'regex blacklist' => ['blacklist', '^spam', 'regex'],
            'unknown type' => ['blacklist', 'spam.pl', 'glob'],
            'unknown list' => ['dnsbl', 'x.pl', 'exact'],
            'empty' => ['whitelist', '', 'exact'],
            'star alone' => ['whitelist', '*', 'wildcard'],
            'star alone blacklist' => ['blacklist', '*', 'wildcard'],
            'everyone' => ['email_whitelist', '*@*', 'wildcard'],
            'whole tld whitelisted' => ['whitelist', '*.pl', 'wildcard'],
            'tld whitelisted via email' => ['email_whitelist', '*@*.pl', 'wildcard'],
            'trailing star' => ['whitelist', 'firma.*', 'wildcard'],
            'star in exact' => ['email_whitelist', '*@firma.pl', 'exact'],
            'not an address' => ['email_whitelist', 'firma.pl', 'exact'],
            'not a domain' => ['whitelist', 'localhost', 'exact'],
            'email pattern without @' => ['email_blacklist', '*.ru', 'wildcard'],
            'spaces' => ['email_blacklist', 'a b@c.pl', 'exact'],
            'quote' => ['whitelist', 'fir"ma.pl', 'exact'],
            'too long' => ['blacklist', str_repeat('a', 253) . '.pl', 'exact'],
        ];
    }

    #[DataProvider('rejected')]
    public function testRejected(string $list, string $value, string $type)
    {
        $this->assertNotNull(UserRulePolicy::validate($list, UserRulePolicy::normalize($list, $value), $type));
    }

    public function testNormalize()
    {
        $this->assertSame('firma.pl', UserRulePolicy::normalize('whitelist', ' @Firma.PL '));
        $this->assertSame('jan@firma.pl', UserRulePolicy::normalize('email_whitelist', 'Jan@Firma.pl'));
    }
}
