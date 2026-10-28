<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\Jobs\JobContext;
use Doctrine\ORM\EntityManagerInterface;

/** Loads the job's account (handlers of account.* jobs). */
trait AccountJobTrait
{
    private function account(EntityManagerInterface $em, JobContext $context, bool $sshOnly = false): Account
    {
        $account = $context->accountId() !== null ? $em->find(Account::class, $context->accountId()) : null;
        if (!$account) {
            throw new \RuntimeException('Konto zostało usunięte.');
        }
        if ($sshOnly && !$account->isSsh()) {
            throw new \RuntimeException('Konto nie jest typu SSH.');
        }
        return $account;
    }
}
