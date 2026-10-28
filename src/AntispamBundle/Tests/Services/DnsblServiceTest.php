<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\DnsblCache;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Repository\DnsblCacheRepository;
use AntispamBundle\Repository\DnsblProviderRepository;
use AntispamBundle\Services\DnsblService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class DnsblServiceTest extends TestCase
{
    /** @var DnsblCache[] persisted cache rows */
    private $persisted = [];
    private $removed = [];
    private $cached = null;

    protected function setUp(): void
    {
        $this->persisted = [];
        $this->removed = [];
        $this->cached = null;
    }

    private function service(callable $resolver)
    {
        $provider = (new DnsblProvider())->setZone('zen.spamhaus.org')->setScore(8)->setCacheTtl(3600)->setEnabled(true);

        $providers = $this->createMock(DnsblProviderRepository::class);
        $providers->method('findEnabled')->willReturn([$provider]);
        $cache = $this->createMock(DnsblCacheRepository::class);
        $cache->method('findFresh')->willReturnCallback(function () { return $this->cached; });

        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturnCallback(function ($class) use ($providers, $cache) {
            return $class === DnsblProvider::class ? $providers : $cache;
        });
        $em->method('persist')->willReturnCallback(function ($e) { $this->persisted[] = $e; });
        $em->method('remove')->willReturnCallback(function ($e) { $this->removed[] = $e; });

        return new DnsblService($em, $resolver);
    }

    public static function responses()
    {
        return [
            'listed (SBL)' => [['127.0.0.2'], true],
            'listed (XBL)' => [['127.0.0.4'], true],
            'URIBL refused' => [['127.0.0.1'], false],
            'Spamhaus public resolver' => [['127.255.255.254'], false],
            'Spamhaus rate limit' => [['127.255.255.255'], false],
            'ISP NXDOMAIN hijack' => [['92.242.132.24'], false],
        ];
    }

    #[DataProvider('responses')]
    public function testOnlyRealListingCodesCount(array $answer, $listed)
    {
        $reasons = [];
        $score = $this->service(function () use ($answer) { return $answer; })->scoreForIp('203.0.113.7', $reasons);

        $this->assertSame($listed ? 8 : 0, $score);
        // Error answers are never cached; real answers are.
        $this->assertCount($listed ? 1 : 0, $this->persisted);
    }

    public function testNotListedIsCached()
    {
        $this->service(function () { return []; })->scoreForIp('203.0.113.7');
        $this->assertCount(1, $this->persisted);
        $this->assertFalse($this->persisted[0]->isListed());
    }

    public function testDnsErrorIsNotCached()
    {
        $this->service(function () { return null; })->scoreForIp('203.0.113.7');
        $this->assertCount(0, $this->persisted);
    }

    public function testPoisonedCacheRowIsDroppedAndAskedAgain()
    {
        $this->cached = (new DnsblCache())->setIp('203.0.113.7')->setZone('zen.spamhaus.org')->setListed(true)->setResponse('127.255.255.254');
        $asked = 0;
        $score = $this->service(function () use (&$asked) { $asked++; return []; })->scoreForIp('203.0.113.7');

        $this->assertSame(0, $score);
        $this->assertSame(1, $asked);
        $this->assertCount(1, $this->removed);
    }

    public function testFreshCacheIsUsed()
    {
        $this->cached = (new DnsblCache())->setIp('203.0.113.7')->setZone('zen.spamhaus.org')->setListed(true)->setResponse('127.0.0.2');
        $score = $this->service(function () { $this->fail('must not query DNS'); })->scoreForIp('203.0.113.7');
        $this->assertSame(8, $score);
    }

    public function testFailingZoneTripsTheBreaker()
    {
        $asked = 0;
        $dnsbl = $this->service(function () use (&$asked) { $asked++; return null; });
        for ($i = 0; $i < 10; $i++) {
            $dnsbl->scoreForIp('203.0.113.' . $i);
        }
        $this->assertSame(DnsblService::MAX_FAILURES, $asked);
    }

    public function testIsListingAddress()
    {
        $this->assertTrue(DnsblService::isListingAddress('127.0.0.10'));
        $this->assertFalse(DnsblService::isListingAddress('127.0.0.1'));
        $this->assertFalse(DnsblService::isListingAddress('127.255.255.252'));
        $this->assertFalse(DnsblService::isListingAddress('10.0.0.2'));
        $this->assertFalse(DnsblService::isListingAddress(null));
    }
}
