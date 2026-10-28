<?php

namespace AntispamBundle\Tests\Entity;

use AntispamBundle\Entity\Account;
use PHPUnit\Framework\TestCase;

class AccountImapCursorTest extends TestCase
{
    public function testCursorRoundTrip()
    {
        $account = new Account();
        $this->assertNull($account->getImapCursor());

        $account->setImapCursor(['uidvalidity' => 123, 'last_uid' => 456]);
        $this->assertSame(['uidvalidity' => 123, 'last_uid' => 456], $account->getImapCursor());

        $account->setImapCursor(null);
        $this->assertNull($account->getImapCursor());
    }

    public function testChangingServerOrLoginForgetsTheCursor()
    {
        $account = (new Account())->setImapHost('imap.a.pl')->setImapLogin('jan');
        $account->setImapCursor(['uidvalidity' => 1, 'last_uid' => 9]);

        // Saving the form with the same values keeps it ("993" from the form vs int 993).
        $account->setImapHost('imap.a.pl')->setImapLogin('jan')->setImapPort('993');
        $this->assertNotNull($account->getImapCursor());

        $account->setImapHost('imap.b.pl');
        $this->assertNull($account->getImapCursor());
    }
}
