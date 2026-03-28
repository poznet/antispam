<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\KeyEncryptionService;
use PHPUnit\Framework\TestCase;

class KeyEncryptionServiceTest extends TestCase
{
    private $service;

    protected function setUp(): void
    {
        $this->service = new KeyEncryptionService('test-secret-key-for-testing');
    }

    public function testEncryptDecryptRoundTrip()
    {
        $original = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        $encrypted = $this->service->encrypt($original);

        $this->assertNotEquals($original, $encrypted);
        $this->assertEquals($original, $this->service->decrypt($encrypted));
    }

    public function testEncryptProducesDifferentOutputEachTime()
    {
        $plaintext = 'test-data';
        $enc1 = $this->service->encrypt($plaintext);
        $enc2 = $this->service->encrypt($plaintext);

        // Different IVs should produce different ciphertext
        $this->assertNotEquals($enc1, $enc2);

        // Both should decrypt to the same value
        $this->assertEquals($plaintext, $this->service->decrypt($enc1));
        $this->assertEquals($plaintext, $this->service->decrypt($enc2));
    }

    public function testEncryptNullReturnsNull()
    {
        $this->assertNull($this->service->encrypt(null));
        $this->assertNull($this->service->encrypt(''));
    }

    public function testDecryptNullReturnsNull()
    {
        $this->assertNull($this->service->decrypt(null));
        $this->assertNull($this->service->decrypt(''));
    }

    public function testDifferentSecretCannotDecrypt()
    {
        $original = 'sensitive-data';
        $encrypted = $this->service->encrypt($original);

        $otherService = new KeyEncryptionService('different-secret');
        $decrypted = $otherService->decrypt($encrypted);

        $this->assertNotEquals($original, $decrypted);
    }
}
