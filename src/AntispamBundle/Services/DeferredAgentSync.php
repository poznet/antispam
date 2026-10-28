<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\Jobs\JobQueue;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Queues a rules push to the agents of SSH+Maildir accounts after a rule
 * change in the user area (/my/rules, "Zawsze akceptuj" in /my/spam) - an SSH
 * login plus an SFTP upload takes seconds, so the page does not wait for it.
 * The push runs as a background job (Jobs\Handler\AccountSyncHandler); one
 * pending sync per account, a change during a running sync queues another.
 *
 * Only accounts with a deployed agent are synced; IMAP accounts read the
 * rules from the database on every scan and need nothing.
 */
class DeferredAgentSync
{
    public function __construct(
        private EntityManagerInterface $em,
        private JobQueue $queue,
    ) {
    }

    /** @return bool true when the account will be synced */
    public function defer(Account $account): bool
    {
        if (!$account->isSsh() || !$account->getAgentDeployed() || $account->getId() === null) {
            return false;
        }
        $this->queue->enqueue(
            BackgroundJob::TYPE_ACCOUNT_SYNC,
            ['background' => true],
            $account,
            label: 'Synchronizacja reguł (zmiana w panelu użytkownika): ' . $account->getEmail(),
            dedupeKey: 'account.sync:' . $account->getId(),
        );
        return true;
    }

    /**
     * Schedule every SSH account whose mailbox address is $owner.
     *
     * @return int number of accounts scheduled
     */
    public function deferForOwner(string $owner): int
    {
        if ($owner === '' || RuleOwnership::isGlobal($owner)) {
            return 0;
        }
        $n = 0;
        foreach ($this->em->getRepository(Account::class)->findBy(['email' => $owner, 'connectionType' => Account::CONNECTION_SSH]) as $account) {
            $n += $this->defer($account) ? 1 : 0;
        }
        return $n;
    }
}
