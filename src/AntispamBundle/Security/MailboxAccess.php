<?php

namespace AntispamBundle\Security;

use AntispamBundle\Entity\User;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Ownership rules: which mailboxes (and so which score-log rows) a panel user
 * may see and act on. Administrators (ROLE_ADMIN, including the legacy
 * environment admin) are unrestricted; a ROLE_USER only gets the Accounts
 * assigned to it. The legacy config-based "imap" mailbox has no Account, so it
 * is admin-only.
 *
 * Every user-area controller action must go through this class - never trust
 * a mailbox key or e-mail address taken from the request.
 */
class MailboxAccess
{
    public function isAdmin(?UserInterface $user): bool
    {
        return $user !== null && in_array(User::ROLE_ADMIN, $user->getRoles(), true);
    }

    /** @return int[] ids of the Accounts assigned to the user (empty for anyone but a User entity) */
    public function accountIds(?UserInterface $user): array
    {
        if (!$user instanceof User) {
            return [];
        }
        $ids = [];
        foreach ($user->getAccounts() as $account) {
            $ids[] = (int)$account->getId();
        }
        return $ids;
    }

    /** @return string[] QuarantineService mailbox keys ("imap-<id>" / "ssh-<id>") of the assigned Accounts */
    public function mailboxKeys(?UserInterface $user): array
    {
        $keys = [];
        if ($user instanceof User) {
            foreach ($user->getAccounts() as $account) {
                $keys[] = ($account->isSsh() ? 'ssh-' : 'imap-') . (int)$account->getId();
            }
        }
        return $keys;
    }

    /**
     * E-mail addresses of the assigned mailboxes (as stored on the Accounts)
     * for score-log scoping, or null when the user is not restricted.
     *
     * @return string[]|null
     */
    public function accountEmails(?UserInterface $user): ?array
    {
        if ($this->isAdmin($user)) {
            return null;
        }
        $emails = [];
        if ($user instanceof User) {
            foreach ($user->getAccounts() as $account) {
                $email = trim((string)$account->getEmail());
                if ($email !== '') {
                    $emails[$email] = $email;
                }
            }
        }
        return array_values($emails);
    }

    /** May the user work with this QuarantineService mailbox key (imap-<id> / ssh-<id> / imap)? */
    public function canAccessMailboxKey(?UserInterface $user, string $key): bool
    {
        if ($user === null) {
            return false;
        }
        if ($this->isAdmin($user)) {
            return true;
        }
        // The key must be exactly the one QuarantineService builds for an
        // assigned account (type prefix + id), no more lenient parsing.
        return in_array($key, $this->mailboxKeys($user), true);
    }

    /**
     * Keep only the mailboxes the user may access.
     *
     * @param array $mailboxes rows of QuarantineService::getMailboxes()
     *
     * @return array
     */
    public function filterMailboxes(?UserInterface $user, array $mailboxes): array
    {
        return array_values(array_filter($mailboxes, fn($m) => $this->canAccessMailboxKey($user, (string)($m['key'] ?? ''))));
    }

    /** May the user see score-log rows of this account e-mail? Case-insensitive, like the mail domain. */
    public function canAccessEmail(?UserInterface $user, ?string $email): bool
    {
        $allowed = $this->accountEmails($user);
        if ($allowed === null) {
            return $user !== null;
        }
        foreach ($allowed as $a) {
            if (strcasecmp($a, (string)$email) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Restrict SpamScoreLogRepository::search() filters to the user's
     * mailboxes. A requested "account" the user does not own is dropped (the
     * scope then covers all of their mailboxes), never honoured.
     */
    public function scopeScoreLogFilters(?UserInterface $user, array $filters): array
    {
        $allowed = $this->accountEmails($user);
        if ($user === null) {
            $allowed = [];
        }
        if ($allowed === null) {
            return $filters;
        }
        if (!empty($filters['account']) && !$this->canAccessEmail($user, $filters['account'])) {
            $filters['account'] = null;
        }
        $filters['accounts'] = $allowed;
        return $filters;
    }
}
