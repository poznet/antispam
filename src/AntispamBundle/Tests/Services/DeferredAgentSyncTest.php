<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\SshService;
use AntispamBundle\Tests\Security\MailboxAccessTest;
use AntispamBundle\Tests\Support\InMemoryRepository;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class DeferredAgentSyncTest extends TestCase
{
    private array $accounts;

    protected function setUp(): void
    {
        $this->accounts = [
            5 => MailboxAccessTest::account(5, 'jan@ssh.pl', Account::CONNECTION_SSH)->setAgentDeployed(true),
            6 => MailboxAccessTest::account(6, 'jan@ssh.pl', Account::CONNECTION_SSH)->setAgentDeployed(false),
            7 => MailboxAccessTest::account(7, 'jan@ssh.pl', Account::CONNECTION_IMAP),
            8 => MailboxAccessTest::account(8, 'ola@ssh.pl', Account::CONNECTION_SSH)->setAgentDeployed(true),
        ];
    }

    private function service(SshService $ssh, ?LoggerInterface $logger = null): DeferredAgentSync
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn(new InMemoryRepository(array_values($this->accounts)));
        $em->method('find')->willReturnCallback(fn($class, $id) => $this->accounts[$id] ?? null);
        $em->method('isOpen')->willReturn(true);
        $exporter = $this->createMock(AgentRulesExporter::class);
        $exporter->method('export')->willReturnCallback(fn($email) => ['owner' => $email]);
        return new DeferredAgentSync($em, $ssh, $exporter, $logger);
    }

    public function testOnlyDeployedSshAccountsOfTheOwnerAreSyncedAfterTheResponse()
    {
        $ssh = $this->createMock(SshService::class);
        $ssh->expects($this->once())->method('syncRules')
            ->with($this->accounts[5], json_encode(['owner' => 'jan@ssh.pl']))
            ->willReturn(['success' => true]);
        $sync = $this->service($ssh);

        $this->assertSame(1, $sync->deferForOwner('JAN@ssh.pl'));
        $this->assertSame(0, $sync->deferForOwner('*'), 'global rules are never pushed from the user area');
        $this->assertTrue($sync->hasPending());

        $response = new Response('ok');
        $sync->onResponse(new ResponseEvent($this->createMock(HttpKernelInterface::class), new Request(), HttpKernelInterface::MAIN_REQUEST, $response));
        $this->assertSame('2', $response->headers->get('Content-Length'));
        $this->assertSame('close', $response->headers->get('Connection'));

        $this->assertSame(1, $sync->runPending());
        $this->assertFalse($sync->hasPending());
        $this->assertSame(0, $sync->runPending(), 'runs once');
    }

    public function testFailuresAreLoggedNotThrown()
    {
        $ssh = $this->createMock(SshService::class);
        $ssh->method('syncRules')->willReturnOnConsecutiveCalls(['success' => false, 'error' => 'agent old'], $this->throwException(new \RuntimeException('down')));
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())->method('warning');
        $logger->expects($this->once())->method('error');
        $sync = $this->service($ssh, $logger);
        $sync->defer($this->accounts[5]);
        $sync->defer($this->accounts[8]);

        $this->assertSame(0, $sync->runPending());
    }

    public function testNothingPendingLeavesTheResponseAlone()
    {
        $sync = $this->service($this->createMock(SshService::class));
        $response = new Response('ok');
        $sync->onResponse(new ResponseEvent($this->createMock(HttpKernelInterface::class), new Request(), HttpKernelInterface::MAIN_REQUEST, $response));
        $this->assertFalse($response->headers->has('Connection'));
        $this->assertFalse($sync->defer($this->accounts[7]), 'IMAP accounts read the database');
    }
}
