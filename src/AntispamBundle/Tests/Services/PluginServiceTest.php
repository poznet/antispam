<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\SpamSignalService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;

class PluginServiceTest extends TestCase
{
    private function service(array $config): PluginService
    {
        $c = $this->createMock(ConfigService::class);
        $c->method('get')->willReturnCallback(fn ($key) => $config[$key] ?? null);
        return new PluginService(
            $this->createMock(EntityManagerInterface::class),
            $this->createMock(CacheItemPoolInterface::class),
            $this->createMock(SpamSignalService::class),
            'secret',
            $c
        );
    }

    public function testMaxUploadDefaultsTo700KiB()
    {
        // Base64 + JSON of 700 KiB stays under nginx's default 1 MiB body limit.
        $this->assertSame(700 * 1024, $this->service([])->getMaxUploadBytes());
        $this->assertLessThan(1024 * 1024, (int)ceil(700 * 1024 / 3) * 4 + 200);
    }

    public function testMaxUploadIsConfigurableAndClamped()
    {
        $this->assertSame(4096 * 1024, $this->service(['plugin.max_upload_kb' => '4096'])->getMaxUploadBytes());
        $this->assertSame(PluginService::MIN_MAX_UPLOAD_KB * 1024, $this->service(['plugin.max_upload_kb' => '1'])->getMaxUploadBytes());
        $this->assertSame(PhishingReportService::MAX_RAW_BYTES, $this->service(['plugin.max_upload_kb' => '999999'])->getMaxUploadBytes());
    }
}
