<?php

namespace AntispamBundle\Tests\Support;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\RuleOwnership;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;

/**
 * In-memory "database" for rule-ownership tests: one InMemoryRepository per
 * entity and an EntityManager mock wired to them (persist() adds).
 */
class RuleFixtures
{
    /** @var array<class-string, InMemoryRepository> */
    public array $repos = [];
    public array $persisted = [];
    public int $flushes = 0;
    public EntityManagerInterface $em;

    public function __construct(TestCase $test, array $accountEmails = [])
    {
        foreach ([Account::class, DnsblProvider::class, Blacklist::class, Whitelist::class, EmailBlacklist::class, EmailWhitelist::class, \AntispamBundle\Entity\ComplexRule::class] as $class) {
            $this->repos[$class] = new InMemoryRepository();
        }
        foreach ($accountEmails as $i => $email) {
            $account = (new Account())->setName('Konto ' . $i)->setEmail($email)->setConnectionType(Account::CONNECTION_SSH)->setAgentDeployed(false);
            $this->repos[Account::class]->add($account);
        }

        $em = (new \ReflectionMethod($test, 'createMock'))->invoke($test, EntityManagerInterface::class);
        $em->method('getRepository')->willReturnCallback(fn($class) => $this->repos[$class]);
        $em->method('persist')->willReturnCallback(function ($entity) {
            $this->persisted[] = $entity;
            $this->repos[get_class($entity)]->add($entity);
        });
        $em->method('flush')->willReturnCallback(function () {
            $this->flushes++;
        });
        $this->em = $em;
    }

    public function ownership(): RuleOwnership
    {
        return new RuleOwnership($this->em);
    }

    public function add(object $rule): object
    {
        $this->repos[get_class($rule)]->add($rule);
        return $rule;
    }
}
