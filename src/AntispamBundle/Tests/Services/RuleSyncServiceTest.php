<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\RuleSyncService;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use PHPUnit\Framework\TestCase;

class RuleSyncServiceTest extends TestCase
{
    public function testExportRulesReturnsCorrectStructure()
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $repo = $this->createMock(EntityRepository::class);
        $repo->method('findBy')->willReturn([]);

        $em->method('getRepository')->willReturn($repo);

        $ssh = $this->createMock(SshService::class);

        $service = new RuleSyncService($em, $ssh);
        $rules = $service->exportRules('test@example.com');

        $this->assertArrayHasKey('whitelist', $rules);
        $this->assertArrayHasKey('email_whitelist', $rules);
        $this->assertArrayHasKey('blacklist', $rules);
        $this->assertArrayHasKey('email_blacklist', $rules);
        $this->assertIsArray($rules['whitelist']);
    }

    public function testGetRuleCountsReturnsZeroForEmpty()
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $repo = $this->createMock(EntityRepository::class);
        $repo->method('findBy')->willReturn([]);

        $em->method('getRepository')->willReturn($repo);

        $ssh = $this->createMock(SshService::class);

        $service = new RuleSyncService($em, $ssh);
        $counts = $service->getRuleCounts('test@example.com');

        $this->assertEquals(0, $counts['whitelist']);
        $this->assertEquals(0, $counts['email_whitelist']);
        $this->assertEquals(0, $counts['blacklist']);
        $this->assertEquals(0, $counts['email_blacklist']);
    }
}
