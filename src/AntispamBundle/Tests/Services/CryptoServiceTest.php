<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\CryptoService;
use PHPUnit\Framework\TestCase;

class CryptoServiceTest extends TestCase
{
    public function testRoundTripAndLegacyPlaintext()
    {
        $c = new CryptoService('secret');
        $enc = $c->encrypt('hasło IMAP');
        $this->assertStringStartsWith(CryptoService::PREFIX, $enc);
        $this->assertNotSame($enc, $c->encrypt('hasło IMAP'), 'random nonce per value');
        $this->assertSame('hasło IMAP', $c->decrypt($enc));
        $this->assertSame($enc, $c->encrypt($enc), 'already encrypted values are kept');

        $this->assertSame('plain', $c->decrypt('plain'));
        $this->assertNull($c->encrypt(null));
        $this->assertSame('', $c->decrypt(''));
    }

    public function testOtherSecretCannotDecrypt()
    {
        $enc = (new CryptoService('secret'))->encrypt('x');
        $this->expectException(\RuntimeException::class);
        (new CryptoService('other'))->decrypt($enc);
    }
}
