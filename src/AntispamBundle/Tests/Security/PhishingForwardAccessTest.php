<?php

namespace AntispamBundle\Tests\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;

/** Forwarding phishing reports to CERT / SOC is administration (ROLE_ADMIN). */
class PhishingForwardAccessTest extends KernelTestCase
{
    public static function paths(): array
    {
        return [['/phishing/1/forward'], ['/phishing/forward'], ['/phishing/forward-settings']];
    }

    #[DataProvider('paths')]
    public function testAdminOnly(string $path)
    {
        self::bootKernel();
        [$attributes] = self::getContainer()->get('security.access_map')->getPatterns(Request::create($path, 'POST'));
        $this->assertSame(['ROLE_ADMIN'], $attributes, $path);
    }
}
