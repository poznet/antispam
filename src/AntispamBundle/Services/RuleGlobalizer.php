<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Turns mailbox rules of the white/black lists into global rules (owner '*',
 * "Wszystkie skrzynki") - the panel action "Zmień na: Wszystkie skrzynki" and
 * the console command antispam:rules:make-global.
 *
 * Duplicates: when a global rule with the same value and pattern type already
 * exists (or was made global earlier in the same batch), the mailbox rule is
 * removed and its hit counter is added to the global one; the global rule
 * keeps its own score. Otherwise the rule itself only gets the new owner, so
 * its id, counter and score are unchanged.
 *
 * Side effects of makeGlobal() (not of reassign()): a moved blacklist rule
 * gets the retroactive pass, which for a global rule covers every account and
 * the legacy mailbox (RetroactiveSpamService::applyRule), and every deployed
 * SSH agent gets an `account.sync` job - its rule export now includes the new
 * global rules (or drops the merged mailbox copy).
 */
class RuleGlobalizer
{
    public const MOVED = 'moved';
    public const MERGED = 'merged';
    public const UNCHANGED = 'unchanged';

    /** list type (audit target type, route suffix) => [entity, field holding the value] */
    public const LISTS = [
        'whitelist' => [Whitelist::class, 'host'],
        'blacklist' => [Blacklist::class, 'host'],
        'email_whitelist' => [EmailWhitelist::class, 'whitelistemail'],
        'email_blacklist' => [EmailBlacklist::class, 'blacklistemail'],
    ];

    public function __construct(
        private EntityManagerInterface $em,
        private ?DeferredRetroactivePass $retroactive = null,
        private ?DeferredAgentSync $agentSync = null,
        private ?AuditLogger $audit = null,
    ) {
    }

    public static function typeOf(object $rule): ?string
    {
        foreach (self::LISTS as $type => [$entity]) {
            if ($rule instanceof $entity) {
                return $type;
            }
        }
        return null;
    }

    public static function valueOf(object $rule): string
    {
        $type = self::typeOf($rule);
        if ($type === null) {
            throw new \InvalidArgumentException('Not a list rule: ' . get_class($rule));
        }
        return (string)$rule->{'get' . ucfirst(self::LISTS[$type][1])}();
    }

    /**
     * Make the rules global without flushing and without side effects (the
     * console command uses this, also for its dry run).
     *
     * @param iterable<object> $rules rules of any of the four lists
     * @return array<int, array{rule: object, outcome: string, from: string, id: int|null}>
     *         one entry per rule; outcome self::MOVED, self::MERGED (removed,
     *         counter added to the existing global rule) or self::UNCHANGED (already global)
     */
    public function reassign(iterable $rules, bool $dryRun = false): array
    {
        $pending = [];
        $out = [];
        foreach ($rules as $rule) {
            $type = self::typeOf($rule);
            if ($type === null) {
                throw new \InvalidArgumentException('Not a list rule: ' . get_class($rule));
            }
            $entry = ['rule' => $rule, 'outcome' => self::UNCHANGED, 'from' => (string)$rule->getEmail(), 'id' => $rule->getId()];
            if (RuleOwnership::isGlobal($rule->getEmail())) {
                $out[] = $entry;
                continue;
            }
            [$entity, $field] = self::LISTS[$type];
            $value = self::valueOf($rule);
            // MySQL compares case-insensitively, so does the in-batch lookup.
            $key = $entity . '|' . strtolower((string)$rule->getPatternType()) . '|' . mb_strtolower($value);
            $global = $pending[$key] ?? $this->em->getRepository($entity)->findOneBy([
                'email' => RuleOwnership::ALL,
                $field => $value,
                'patternType' => $rule->getPatternType(),
            ]);
            if ($global !== null && $global !== $rule) {
                if (!$dryRun) {
                    $global->setCounter((int)$global->getCounter() + (int)$rule->getCounter());
                    $this->em->remove($rule);
                }
                $entry['outcome'] = self::MERGED;
            } else {
                if (!$dryRun) {
                    $rule->setEmail(RuleOwnership::ALL);
                }
                // A second copy of the value in the same batch merges into this one.
                $pending[$key] = $rule;
                $entry['outcome'] = self::MOVED;
            }
            $out[] = $entry;
        }
        return $out;
    }

    /**
     * Make the rules global, flush, audit (`rule.make_global` per rule) and
     * queue the side effects.
     *
     * @param object[] $rules rules of any of the four lists
     * @return array{moved: int, merged: int, unchanged: int, retroactive: \AntispamBundle\Services\Jobs\EnqueueResult[], synced: int}
     */
    public function makeGlobal(array $rules): array
    {
        $result = ['moved' => 0, 'merged' => 0, 'unchanged' => 0, 'retroactive' => [], 'synced' => 0];
        $changed = [];
        foreach ($this->reassign($rules) as $entry) {
            $result[$entry['outcome']]++;
            if ($entry['outcome'] !== self::UNCHANGED) {
                $changed[] = [$entry['rule'], $entry['outcome'], $entry['from'], $entry['id']];
            }
        }
        if (!$changed) {
            return $result;
        }
        $this->em->flush();

        foreach ($changed as [$rule, $outcome, $oldOwner, $id]) {
            $type = self::typeOf($rule);
            $details = ['from' => $oldOwner, 'merged' => $outcome === self::MERGED, 'pattern_type' => $rule->getPatternType()];
            if ($rule instanceof Blacklist || $rule instanceof EmailBlacklist) {
                $details['score'] = $rule->getScore();
            }
            $this->audit?->log('rule.make_global', targetType: $type, targetId: $id, label: self::valueOf($rule), mailbox: RuleOwnership::ALL, details: $details);

            // Merged: the existing global rule already applied to every mailbox.
            if ($outcome === self::MOVED && $this->retroactive !== null && ($rule instanceof Blacklist || $rule instanceof EmailBlacklist)) {
                $queued = $this->retroactive->queue($rule);
                if ($queued !== null) {
                    $result['retroactive'][] = $queued;
                }
            }
        }
        $result['synced'] = $this->agentSync?->deferAll('zmiana reguł na wszystkie skrzynki') ?? 0;
        return $result;
    }
}
