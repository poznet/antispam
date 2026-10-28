<?php

namespace AntispamBundle\Tests\Entity;

use AntispamBundle\Entity\Account;
use PHPUnit\Framework\TestCase;

class AccountMarkScannedTest extends TestCase
{
    public function testOnlyFirstScanIsFlaggedInitial()
    {
        $account = new Account();

        $account->markScanned(['total' => 120]);
        $this->assertNotNull($account->getLastScanAt());
        $this->assertTrue($account->getLastScanResultDecoded()['initial']);

        $account->markScanned(['total' => 3]);
        $this->assertArrayNotHasKey('initial', $account->getLastScanResultDecoded());
        $this->assertSame(3, $account->getLastScanResultDecoded()['total']);
    }
}
