<?php

namespace AntispamBundle\Tests\Command;

use AntispamBundle\Command\RulesMakeGlobalCommand;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Services\RuleOwnership;
use AntispamBundle\Tests\Support\RuleFixtures;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

class RulesMakeGlobalCommandTest extends TestCase
{
    private RuleFixtures $db;
    private array $removed = [];

    protected function setUp(): void
    {
        $this->db = new RuleFixtures($this, ['jan@firma.pl']);
        $this->db->em->method('remove')->willReturnCallback(function ($e) { $this->removed[] = $e; });
    }

    private function run_(array $args): string
    {
        $tester = new CommandTester(new RulesMakeGlobalCommand($this->db->em, $this->db->ownership()));
        $tester->execute($args);
        return $tester->getDisplay();
    }

    public function testOwnerRulesBecomeGlobalOthersUntouched()
    {
        $owned = $this->db->add((new Blacklist())->setEmail('biuro@firma.pl')->setHost('spam.example')->setCounter(3));
        $wl = $this->db->add((new EmailWhitelist())->setEmail('biuro@firma.pl')->setWhitelistemail('szef@firma.pl'));
        $other = $this->db->add((new Blacklist())->setEmail('jan@firma.pl')->setHost('other.example'));

        $out = $this->run_(['--owner' => 'biuro@firma.pl']);

        $this->assertSame(RuleOwnership::ALL, $owned->getEmail());
        $this->assertSame(RuleOwnership::ALL, $wl->getEmail());
        $this->assertSame('jan@firma.pl', $other->getEmail());
        $this->assertStringContainsString('2 rule(s) of biuro@firma.pl made global', $out);
        $this->assertSame([], $this->removed);
    }

    public function testDuplicateOfGlobalRuleIsMergedNotDuplicated()
    {
        $global = $this->db->add((new Blacklist())->setEmail(RuleOwnership::ALL)->setHost('spam.example')->setCounter(2));
        $owned = $this->db->add((new Blacklist())->setEmail('biuro@firma.pl')->setHost('spam.example')->setCounter(5));

        $this->run_(['--owner' => 'biuro@firma.pl']);

        $this->assertSame([$owned], $this->removed);
        $this->assertSame(7, $global->getCounter());
    }

    public function testDryRunChangesNothing()
    {
        $owned = $this->db->add((new Blacklist())->setEmail('biuro@firma.pl')->setHost('spam.example'));

        $out = $this->run_(['--owner' => 'biuro@firma.pl', '--dry-run' => true]);

        $this->assertSame('biuro@firma.pl', $owned->getEmail());
        $this->assertSame(0, $this->db->flushes);
        $this->assertStringContainsString('[dry run] 1 rule(s)', $out);
    }

    public function testExplicitOwner()
    {
        $rule = $this->db->add((new Blacklist())->setEmail('jan@firma.pl')->setHost('x.example'));
        $this->run_(['--owner' => 'jan@firma.pl']);
        $this->assertSame(RuleOwnership::ALL, $rule->getEmail());
    }

    public function testOwnerIsRequired()
    {
        $rule = $this->db->add((new Blacklist())->setEmail('jan@firma.pl')->setHost('x.example'));
        $this->assertStringContainsString('--owner=address', $this->run_([]));
        $this->assertStringContainsString('--owner=address', $this->run_(['--owner' => '*']));
        $this->assertSame('jan@firma.pl', $rule->getEmail());
        $this->assertSame(0, $this->db->flushes);
    }
}
