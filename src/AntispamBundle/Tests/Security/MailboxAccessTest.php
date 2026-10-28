<?php

namespace AntispamBundle\Tests\Security;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;

class MailboxAccessTest extends TestCase
{
    public static function account(int $id, string $email, string $type = Account::CONNECTION_IMAP): Account
    {
        $a = (new Account())->setName('acc' . $id)->setEmail($email)->setConnectionType($type);
        $r = new \ReflectionProperty(Account::class, 'id');
        $r->setValue($a, $id);
        return $a;
    }

    public static function user(string $role, array $accounts): User
    {
        return (new User())->setUsername('u')->setPassword('x')->setRole($role)->setAccounts($accounts);
    }

    public function testUserOnlyGetsAssignedMailboxKeys()
    {
        $access = new MailboxAccess();
        $user = self::user(User::ROLE_USER, [self::account(5, 'jan@firma.pl'), self::account(7, 'jan@ssh.pl', Account::CONNECTION_SSH)]);

        $this->assertTrue($access->canAccessMailboxKey($user, 'imap-5'));
        $this->assertTrue($access->canAccessMailboxKey($user, 'ssh-7'));
        // Right id, wrong connection type: not a key of an assigned account.
        $this->assertFalse($access->canAccessMailboxKey($user, 'ssh-5'));
        $this->assertFalse($access->canAccessMailboxKey($user, 'imap-7'));
        $this->assertFalse($access->canAccessMailboxKey($user, 'imap-6'));
        $this->assertFalse($access->canAccessMailboxKey($user, 'ssh-8'));
        $this->assertFalse($access->canAccessMailboxKey($user, 'ssh-50'));
    }

    public function testLegacyImapMailboxAndMalformedKeysAreAdminOnly()
    {
        $access = new MailboxAccess();
        $user = self::user(User::ROLE_USER, [self::account(5, 'jan@firma.pl')]);

        foreach (['imap', '', 'imap-', 'imap-5x', "imap-5\n", 'imap-05a', '../imap-5', 'IMAP-5', 'imap-5 ', 'foo-5'] as $key) {
            $this->assertFalse($access->canAccessMailboxKey($user, $key), var_export($key, true));
        }
        $this->assertTrue($access->canAccessMailboxKey(self::user(User::ROLE_ADMIN, []), 'imap'));
    }

    public function testUserWithoutAccountsSeesNothing()
    {
        $access = new MailboxAccess();
        $user = self::user(User::ROLE_USER, []);

        $this->assertFalse($access->canAccessMailboxKey($user, 'imap-1'));
        $this->assertSame([], $access->accountEmails($user));
        $this->assertFalse($access->canAccessEmail($user, 'anyone@x.pl'));
        $this->assertEquals(['accounts' => [], 'account' => null], $access->scopeScoreLogFilters($user, ['account' => 'anyone@x.pl']));
    }

    public function testAdminsAreUnrestricted()
    {
        $access = new MailboxAccess();
        $dbAdmin = self::user(User::ROLE_ADMIN, []);
        $envAdmin = new InMemoryUser('admin', 'hash', ['ROLE_ADMIN']);

        foreach ([$dbAdmin, $envAdmin] as $admin) {
            $this->assertTrue($access->isAdmin($admin));
            $this->assertTrue($access->canAccessMailboxKey($admin, 'ssh-99'));
            $this->assertNull($access->accountEmails($admin));
            $this->assertTrue($access->canAccessEmail($admin, 'x@y.pl'));
            $this->assertSame(['account' => 'x@y.pl'], $access->scopeScoreLogFilters($admin, ['account' => 'x@y.pl']));
        }
    }

    public function testAnonymousAndForeignUserTypesGetNothing()
    {
        $access = new MailboxAccess();
        $plain = new InMemoryUser('someone', 'x', ['ROLE_USER']);

        $this->assertFalse($access->canAccessMailboxKey(null, 'imap-1'));
        $this->assertFalse($access->canAccessMailboxKey($plain, 'imap-1'));
        $this->assertFalse($access->canAccessEmail(null, 'a@b.pl'));
        $this->assertSame([], $access->scopeScoreLogFilters(null, [])['accounts']);
        $this->assertSame([], $access->scopeScoreLogFilters($plain, [])['accounts']);
    }

    public function testFilterMailboxesDropsForeignOnes()
    {
        $access = new MailboxAccess();
        $user = self::user(User::ROLE_USER, [self::account(5, 'jan@firma.pl')]);
        $rows = [['key' => 'imap'], ['key' => 'imap-4'], ['key' => 'imap-5'], ['key' => 'ssh-9']];

        $this->assertSame([['key' => 'imap-5']], $access->filterMailboxes($user, $rows));
    }

    public function testScoreLogScopeIgnoresForeignAccountFilter()
    {
        $access = new MailboxAccess();
        $user = self::user(User::ROLE_USER, [self::account(5, 'Jan@Firma.pl'), self::account(6, 'jan2@firma.pl')]);

        $f = $access->scopeScoreLogFilters($user, ['account' => 'boss@firma.pl', 'decision' => 'spam']);
        $this->assertNull($f['account']);
        $this->assertSame(['Jan@Firma.pl', 'jan2@firma.pl'], $f['accounts']);
        $this->assertSame('spam', $f['decision']);

        $own = $access->scopeScoreLogFilters($user, ['account' => 'jan@firma.pl']);
        $this->assertSame('jan@firma.pl', $own['account']);
    }

    public function testUserRolesAndSessionSerialization()
    {
        $user = self::user(User::ROLE_USER, [self::account(5, 'a@b.pl')]);
        $this->assertSame([User::ROLE_USER], $user->getRoles());
        $this->assertEqualsCanonicalizing([User::ROLE_ADMIN, User::ROLE_USER], self::user(User::ROLE_ADMIN, [])->getRoles());

        $data = $user->__serialize();
        $this->assertArrayNotHasKey("\0*\0accounts", $data);
        $this->assertNotSame('x', $data['password'], 'only a hash of the password hash goes into the session');
    }
}
