<?php

namespace AntispamBundle\Tests\Entity;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\ScanLog;
use PHPUnit\Framework\TestCase;

class ScanLogTest extends TestCase
{
    public function testFromScanResult()
    {
        $account = new Account();
        $account->setName('Test');
        $account->setConnectionType(Account::CONNECTION_SSH);

        $result = [
            'total' => 100,
            'checked' => 80,
            'skipped' => 20,
            'whitelisted' => 30,
            'blacklisted' => 10,
            'moved_to_spam' => 10,
        ];

        $log = ScanLog::fromScanResult($account, $result, 1500);

        $this->assertEquals($account, $log->getAccount());
        $this->assertEquals('ssh', $log->getScanType());
        $this->assertInstanceOf(\DateTime::class, $log->getScannedAt());
        $this->assertEquals(1500, $log->getDurationMs());
        $this->assertEquals(100, $log->getTotalMessages());
        $this->assertEquals(80, $log->getChecked());
        $this->assertEquals(20, $log->getSkipped());
        $this->assertEquals(30, $log->getWhitelisted());
        $this->assertEquals(10, $log->getBlacklisted());
        $this->assertEquals(10, $log->getMovedToSpam());
        $this->assertTrue($log->getSuccess());
        $this->assertNull($log->getErrorMessage());
    }

    public function testFromError()
    {
        $account = new Account();
        $account->setName('Test');
        $account->setConnectionType(Account::CONNECTION_IMAP);

        $log = ScanLog::fromError($account, 'Connection timeout', 500);

        $this->assertEquals($account, $log->getAccount());
        $this->assertEquals('imap', $log->getScanType());
        $this->assertEquals(500, $log->getDurationMs());
        $this->assertFalse($log->getSuccess());
        $this->assertEquals('Connection timeout', $log->getErrorMessage());
        $this->assertEquals(0, $log->getTotalMessages());
    }

    public function testDefaultValues()
    {
        $log = new ScanLog();

        $this->assertEquals(0, $log->getTotalMessages());
        $this->assertEquals(0, $log->getChecked());
        $this->assertEquals(0, $log->getSkipped());
        $this->assertEquals(0, $log->getWhitelisted());
        $this->assertEquals(0, $log->getBlacklisted());
        $this->assertEquals(0, $log->getMovedToSpam());
        $this->assertTrue($log->getSuccess());
    }
}
