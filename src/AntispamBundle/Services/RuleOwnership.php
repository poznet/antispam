<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Who a white/blacklist rule belongs to.
 *
 * Every rule entity (Whitelist, EmailWhitelist, Blacklist, EmailBlacklist)
 * stores its owner in the NOT NULL `email` column:
 *  - a mailbox address (an Account e-mail): the rule applies to that mailbox only,
 *  - RuleOwnership::ALL ('*'): a global rule, applied to every mailbox.
 *
 * '*' is never a valid mailbox address, keeps the column NOT NULL and works
 * in a plain `IN (...)` lookup, so consumers only need
 * findBy(['email' => RuleOwnership::scope($mailbox)]).
 */
class RuleOwnership
{
    public const ALL = '*';
    public const ALL_LABEL = 'Wszystkie skrzynki';

    public function __construct(
        private EntityManagerInterface $em,
    ) {
    }

    /** Owner values whose rules apply to mailbox $email: its own and the global ones. */
    public static function scope($email): array
    {
        $email = trim((string)$email);
        return $email === '' || $email === self::ALL ? [self::ALL] : [$email, self::ALL];
    }

    public static function isGlobal($owner): bool
    {
        return (string)$owner === self::ALL;
    }

    /**
     * Owners selectable in the panel forms: [owner value => label], global first.
     *
     * @return array<string, string>
     */
    public function choices(): array
    {
        $choices = [self::ALL => self::ALL_LABEL];
        $accounts = $this->em->getRepository(Account::class)->findBy([], ['email' => 'ASC']);
        foreach ($accounts as $account) {
            $email = trim((string)$account->getEmail());
            if ($email === '' || $this->findKey($choices, $email) !== null) {
                continue;
            }
            $name = trim((string)$account->getName());
            $choices[$email] = $name !== '' && strcasecmp($name, $email) !== 0 ? $email . ' (' . $name . ')' : $email;
        }
        return $choices;
    }

    /** Preselected owner: global (every mailbox). */
    public function defaultOwner(): string
    {
        return self::ALL;
    }

    /**
     * Owner submitted by a form, validated against choices(). A missing value
     * falls back to defaultOwner(); an unknown one gives null (reject it).
     */
    public function resolve($requested): ?string
    {
        $requested = trim((string)$requested);
        if ($requested === '') {
            return $this->defaultOwner();
        }
        return $this->findKey($this->choices(), $requested);
    }

    /**
     * Rule that already covers ($owner, $value): one with the same owner or a
     * global one. Dedupe is per owner - the same value may exist for two
     * mailboxes - and a mailbox rule is redundant next to an identical global one.
     */
    public function findDuplicate(string $entity, string $field, string $owner, string $value): ?object
    {
        return $this->em->getRepository($entity)->findOneBy([
            'email' => self::scope($owner),
            $field => $value,
        ]);
    }

    /**
     * Labels for the owner filter/column of a list: the selectable owners plus
     * any owner still present in $rules (e.g. a deleted account) marked as such.
     *
     * @return array<string, string>
     */
    public function labelsFor(iterable $rules): array
    {
        $labels = $this->choices();
        foreach ($rules as $rule) {
            $owner = (string)$rule->getEmail();
            if ($this->findKey($labels, $owner) === null) {
                $labels[$owner] = ($owner === '' ? '(brak skrzynki)' : $owner) . ' - nieaktywna';
            }
        }
        return $labels;
    }

    /** Rules owned by exactly $owner ('*' = global rules only); no filter for null/''. */
    public static function filterByOwner(array $rules, ?string $owner): array
    {
        if ($owner === null || $owner === '') {
            return array_values($rules);
        }
        return array_values(array_filter($rules, fn($rule) => strcasecmp((string)$rule->getEmail(), $owner) === 0));
    }

    /** Case-insensitive key lookup (MySQL compares the column case-insensitively too). */
    private function findKey(array $choices, string $value): ?string
    {
        foreach (array_keys($choices) as $key) {
            if (strcasecmp((string)$key, $value) === 0) {
                return (string)$key;
            }
        }
        return null;
    }
}
