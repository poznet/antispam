<?php

namespace AntispamBundle\Repository;

use AntispamBundle\Entity\ComplexRule;
use AntispamBundle\Services\RuleOwnership;
use Doctrine\ORM\EntityRepository;

class ComplexRuleRepository extends EntityRepository
{
    /**
     * Rules applied to mailbox $email: its own plus the global ones, in id order.
     *
     * @return ComplexRule[]
     */
    public function forMailbox($email, bool $enabledOnly = true): array
    {
        $criteria = ['email' => RuleOwnership::scope($email)];
        if ($enabledOnly) {
            $criteria['enabled'] = true;
        }
        return $this->findBy($criteria, ['id' => 'ASC']);
    }

    public function countOwnedBy(string $owner): int
    {
        return $this->count(['email' => $owner]);
    }
}
