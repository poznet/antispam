<?php

namespace AntispamBundle\Tests\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * access_control rules that every logged-in role (and anonymous visitors) must
 * pass - the firewall is lazy, so these are checked before e.g. logout runs.
 */
class AccessControlTest extends KernelTestCase
{
    public static function publicPaths(): array
    {
        return [['/logout'], ['/login'], ['/'], ['/api/plugin/status'], ['/plugin/download'], ['/q/abc'], ['/health'], ['/metrics']];
    }

    #[DataProvider('publicPaths')]
    public function testPathIsPublic(string $path)
    {
        self::bootKernel();
        [$attributes] = self::getContainer()->get('security.access_map')->getPatterns(Request::create($path));
        $this->assertSame(['PUBLIC_ACCESS'], $attributes, $path);
    }

    public function testSystemStatusPageIsAdminOnly()
    {
        self::bootKernel();
        foreach (['/system/status', '/healthz', '/health/x', '/metrics/x'] as $path) {
            [$attributes] = self::getContainer()->get('security.access_map')->getPatterns(Request::create($path));
            $this->assertSame(['ROLE_ADMIN'], $attributes, $path);
        }
    }

    public function testAdminAreaStaysAdmin()
    {
        self::bootKernel();
        [$attributes] = self::getContainer()->get('security.access_map')->getPatterns(Request::create('/logout-not-really'));
        $this->assertSame(['ROLE_ADMIN'], $attributes);
    }
}
