<?php

namespace AntispamBundle\Tests\Support;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\RuleOwnership;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;

/**
 * In-memory "database" for rule-ownership tests: one InMemoryRepository per
 * entity, an EntityManager mock wired to them (persist() adds), and a
 * ConfigService mock for the legacy mailbox setting.
 */
class RuleFixtures
{
    /** @var array<class-string, InMemoryRepository> */
    public array $repos = [];
    public array $persisted = [];
    public int $flushes = 0;
    public EntityManagerInterface $em;
    public ConfigService $config;

    public function __construct(TestCase $test, ?string $legacyEmail, array $accountEmails = [])
    {
        foreach ([Account::class, DnsblProvider::class, Blacklist::class, Whitelist::class, EmailBlacklist::class, EmailWhitelist::class] as $class) {
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

        $config = (new \ReflectionMethod($test, 'createMock'))->invoke($test, ConfigService::class);
        $config->method('get')->willReturnCallback(fn($name) => $name === 'email' ? $legacyEmail : null);
        $this->config = $config;
    }

    public function ownership(): RuleOwnership
    {
        return new RuleOwnership($this->em, $this->config);
    }

    public function add(object $rule): object
    {
        $this->repos[get_class($rule)]->add($rule);
        return $rule;
    }
}
