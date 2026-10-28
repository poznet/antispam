<?php

namespace AntispamBundle\Tests\Security\TwoFactor;

use AntispamBundle\Security\TwoFactor\Totp;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class TotpTest extends TestCase
{
    /** RFC 6238 appendix B, SHA1 seed "12345678901234567890" (last 6 digits of the 8-digit values). */
    private const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    public static function rfcVectors(): array
    {
        return [[59, '287082'], [1111111109, '081804'], [1111111111, '050471'], [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130']];
    }

    #[DataProvider('rfcVectors')]
    public function testRfc6238Vectors(int $time, string $code)
    {
        $this->assertSame($code, Totp::code(self::RFC_SECRET, Totp::counterAt($time)));
        $this->assertSame(Totp::counterAt($time), Totp::verify(self::RFC_SECRET, $code, null, $time));
    }

    public function testBase32RoundTrip()
    {
        $this->assertSame(self::RFC_SECRET, Totp::base32Encode('12345678901234567890'));
        $this->assertSame('12345678901234567890', Totp::base32Decode(strtolower(self::RFC_SECRET)));
        $bytes = random_bytes(20);
        $this->assertSame($bytes, Totp::base32Decode(Totp::base32Encode($bytes)));
    }

    public function testGeneratedSecretIs160Bits()
    {
        $secret = Totp::generateSecret();
        $this->assertSame(32, strlen($secret));
        $this->assertTrue(Totp::isValidSecret($secret));
        $this->assertNotSame($secret, Totp::generateSecret());
    }

    public function testWindowAcceptsOneStepOfDriftOnly()
    {
        $t = 1700000000;
        $c = Totp::counterAt($t);
        $this->assertSame($c - 1, Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $c - 1), null, $t));
        $this->assertSame($c + 1, Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $c + 1), null, $t));
        $this->assertNull(Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $c - 2), null, $t));
        $this->assertNull(Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $c + 2), null, $t));
    }

    public function testReplayOfAUsedStepIsRefused()
    {
        $t = 1700000000;
        $c = Totp::counterAt($t);
        $code = Totp::code(self::RFC_SECRET, $c);
        $this->assertSame($c, Totp::verify(self::RFC_SECRET, $code, $c - 1, $t));
        $this->assertNull(Totp::verify(self::RFC_SECRET, $code, $c, $t), 'same step twice');
        $this->assertNull(Totp::verify(self::RFC_SECRET, Totp::code(self::RFC_SECRET, $c - 1), $c, $t), 'older step after a newer one');
    }

    public function testGarbageIsRefused()
    {
        foreach (['', '12345', '1234567', 'abcdef', '12 34 5x'] as $code) {
            $this->assertNull(Totp::verify(self::RFC_SECRET, $code), $code);
        }
        $this->assertNull(Totp::verify('', '123456'));
        $this->assertNull(Totp::verify('SHORT', '123456'));
        $this->assertFalse(Totp::isValidSecret('not base32 !!'));
    }

    public function testProvisioningUri()
    {
        $uri = Totp::provisioningUri(self::RFC_SECRET, 'jan@firma.pl', 'Antispam Pancernapanda');
        $this->assertStringStartsWith('otpauth://totp/Antispam%20Pancernapanda:jan%40firma.pl?', $uri);
        $this->assertStringContainsString('secret=' . self::RFC_SECRET, $uri);
        $this->assertStringContainsString('issuer=Antispam%20Pancernapanda', $uri);
        $this->assertStringContainsString('digits=6', $uri);
    }
}
