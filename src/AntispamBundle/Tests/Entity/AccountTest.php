<?php

namespace AntispamBundle\Tests\Entity;

use AntispamBundle\Entity\Account;
use PHPUnit\Framework\TestCase;

class AccountTest extends TestCase
{
    public function testDefaultValues()
    {
        $account = new Account();

        $this->assertEquals(Account::CONNECTION_IMAP, $account->getConnectionType());
        $this->assertTrue($account->isImap());
        $this->assertFalse($account->isSsh());
        $this->assertEquals(143, $account->getImapPort());
        $this->assertEquals(22, $account->getSshPort());
        $this->assertEquals('~/Maildir', $account->getMaildirPath());
        $this->assertEquals('~/antispam-agent', $account->getAgentPath());
        $this->assertFalse($account->getDeleteSpam());
        $this->assertFalse($account->getAgentDeployed());
        $this->assertFalse($account->getNeedsSync());
        $this->assertNull($account->getLastSyncAt());
        $this->assertNull($account->getLastScanAt());
        $this->assertNull($account->getLastScanResult());
    }

    public function testSshConnectionType()
    {
        $account = new Account();
        $account->setConnectionType(Account::CONNECTION_SSH);

        $this->assertTrue($account->isSsh());
        $this->assertFalse($account->isImap());
    }

    public function testFluentSetters()
    {
        $account = new Account();
        $result = $account->setName('Test')
            ->setEmail('test@example.com')
            ->setSshHost('ssh.example.com')
            ->setSshPort(2222)
            ->setSshUser('user')
            ->setNeedsSync(true);

        $this->assertInstanceOf(Account::class, $result);
        $this->assertEquals('Test', $account->getName());
        $this->assertEquals('test@example.com', $account->getEmail());
        $this->assertEquals('ssh.example.com', $account->getSshHost());
        $this->assertEquals(2222, $account->getSshPort());
        $this->assertEquals('user', $account->getSshUser());
        $this->assertTrue($account->getNeedsSync());
    }

    public function testLastScanResultDecoded()
    {
        $account = new Account();

        $this->assertNull($account->getLastScanResultDecoded());

        $data = ['total' => 10, 'spam' => 2];
        $account->setLastScanResult(json_encode($data));
        $decoded = $account->getLastScanResultDecoded();

        $this->assertEquals(10, $decoded['total']);
        $this->assertEquals(2, $decoded['spam']);
    }

    public function testHasSshKeyWithPrivateKey()
    {
        $account = new Account();
        $this->assertFalse($account->hasSshKey());

        $account->setSshKeyPrivate('some-key-content');
        $this->assertTrue($account->hasSshKey());
    }

    public function testSshKeyPassphrase()
    {
        $account = new Account();
        $this->assertNull($account->getSshKeyPassphrase());

        $account->setSshKeyPassphrase('encrypted-passphrase');
        $this->assertEquals('encrypted-passphrase', $account->getSshKeyPassphrase());
    }

    public function testLastSyncAt()
    {
        $account = new Account();
        $this->assertNull($account->getLastSyncAt());

        $now = new \DateTime();
        $account->setLastSyncAt($now);
        $this->assertEquals($now, $account->getLastSyncAt());
    }
}
