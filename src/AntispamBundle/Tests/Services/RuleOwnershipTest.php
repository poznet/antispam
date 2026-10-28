<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Services\RuleOwnership;
use AntispamBundle\Tests\Support\RuleFixtures;
use PHPUnit\Framework\TestCase;

class RuleOwnershipTest extends TestCase
{
    public function testScopeIsTheMailboxPlusGlobalRules()
    {
        $this->assertSame(['jan@firma.pl', '*'], RuleOwnership::scope('jan@firma.pl'));
        $this->assertSame(['jan@firma.pl', '*'], RuleOwnership::scope(' jan@firma.pl '));
        // No mailbox address (legacy mailbox without an e-mail set): global rules only.
        $this->assertSame(['*'], RuleOwnership::scope(null));
        $this->assertSame(['*'], RuleOwnership::scope(''));
        $this->assertSame(['*'], RuleOwnership::scope('*'));
    }

    public function testChoicesListGlobalLegacyAndAccounts()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl', ['jan@firma.pl', 'BIURO@firma.pl', 'anna@firma.pl']);
        $choices = $db->ownership()->choices();

        $this->assertSame(['*', 'biuro@firma.pl', 'jan@firma.pl', 'anna@firma.pl'], array_keys($choices));
        $this->assertSame('Wszystkie skrzynki', $choices['*']);
        $this->assertStringContainsString('z ustawień', $choices['biuro@firma.pl']);
    }

    public function testDefaultOwnerIsLegacyMailboxThenGlobal()
    {
        $this->assertSame('biuro@firma.pl', (new RuleFixtures($this, 'biuro@firma.pl'))->ownership()->defaultOwner());
        $this->assertSame('*', (new RuleFixtures($this, null))->ownership()->defaultOwner());
        $this->assertSame('*', (new RuleFixtures($this, '  '))->ownership()->defaultOwner());
    }

    public function testResolveAcceptsOnlyKnownOwners()
    {
        $ownership = (new RuleFixtures($this, 'biuro@firma.pl', ['jan@firma.pl']))->ownership();

        $this->assertSame('jan@firma.pl', $ownership->resolve('jan@firma.pl'));
        $this->assertSame('jan@firma.pl', $ownership->resolve('JAN@firma.pl'), 'canonical spelling of the account');
        $this->assertSame('*', $ownership->resolve('*'));
        $this->assertSame('biuro@firma.pl', $ownership->resolve(''), 'missing field = legacy default');
        $this->assertSame('biuro@firma.pl', $ownership->resolve(null));
        $this->assertNull($ownership->resolve('obcy@example.com'));
    }

    public function testResolveWithoutLegacyMailboxNeverGivesNull()
    {
        $ownership = (new RuleFixtures($this, null))->ownership();
        $this->assertSame('*', $ownership->resolve(null));
        $this->assertSame('*', $ownership->resolve('*'));
    }

    public function testDuplicateIsPerOwnerAndGlobalCoversEveryMailbox()
    {
        $db = new RuleFixtures($this, null, ['jan@firma.pl', 'anna@firma.pl']);
        $db->add((new Blacklist())->setEmail('jan@firma.pl')->setHost('spam.example'));
        $db->add((new Blacklist())->setEmail('*')->setHost('global.example'));
        $ownership = $db->ownership();

        $this->assertNotNull($ownership->findDuplicate(Blacklist::class, 'host', 'jan@firma.pl', 'spam.example'));
        $this->assertNotNull($ownership->findDuplicate(Blacklist::class, 'host', 'jan@firma.pl', 'SPAM.example'));
        $this->assertNull($ownership->findDuplicate(Blacklist::class, 'host', 'anna@firma.pl', 'spam.example'), 'same value for another mailbox is allowed');
        $this->assertNull($ownership->findDuplicate(Blacklist::class, 'host', '*', 'spam.example'), 'a global rule may be added next to a mailbox rule');
        $this->assertNotNull($ownership->findDuplicate(Blacklist::class, 'host', 'anna@firma.pl', 'global.example'), 'already covered by the global rule');
    }

    public function testLabelsMarkOwnersThatNoLongerExist()
    {
        $db = new RuleFixtures($this, null, ['jan@firma.pl']);
        $rules = [
            (new EmailWhitelist())->setEmail('jan@firma.pl')->setWhitelistemail('a@b.pl'),
            (new EmailWhitelist())->setEmail('stare@firma.pl')->setWhitelistemail('c@d.pl'),
        ];
        $labels = $db->ownership()->labelsFor($rules);

        $this->assertSame(['*', 'jan@firma.pl', 'stare@firma.pl'], array_keys($labels));
        $this->assertStringContainsString('nieaktywna', $labels['stare@firma.pl']);
    }

    public function testFilterByOwner()
    {
        $a = (new Blacklist())->setEmail('jan@firma.pl')->setHost('a.example');
        $b = (new Blacklist())->setEmail('*')->setHost('b.example');
        $c = (new Blacklist())->setEmail('anna@firma.pl')->setHost('c.example');

        $this->assertSame([$a, $b, $c], RuleOwnership::filterByOwner([$a, $b, $c], ''));
        $this->assertSame([$a, $b, $c], RuleOwnership::filterByOwner([$a, $b, $c], null));
        $this->assertSame([$a], RuleOwnership::filterByOwner([$a, $b, $c], 'JAN@firma.pl'));
        $this->assertSame([$b], RuleOwnership::filterByOwner([$a, $b, $c], '*'));
    }
}
