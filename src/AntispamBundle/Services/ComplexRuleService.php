<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\ComplexRule;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Complex rules (docs/complex-rules.md): loading per mailbox, applying them
 * to a message, validating form / API input. Shared by the IMAP pipeline
 * (CheckComplexRules), the plugin scanner (RawMessageScanner), the panel and
 * the plugin API.
 *
 * Order (as on the agent and in the plugin): whitelist rules first - the
 * first match whitelists the message and nothing else is evaluated; then
 * every other rule: spam = always spam, quarantine = at least quarantine,
 * score = its points (may be negative). Spam / quarantine rules add their
 * points too, so the score log shows them.
 */
class ComplexRuleService implements RuntimeCacheInterface
{
    /** Rules a mailbox may own. */
    public const MAX_PER_OWNER = 200;

    /** @var array<string, ComplexRule[]> */
    private array $cache = [];

    public function __construct(private EntityManagerInterface $em, private ?SenderIntelService $intel = null)
    {
    }

    /** Message view with the sender lookups (MX, domain age) wired in. */
    public function message(string $headerBlock, ?\Closure $rawLoader = null, ?string $mailbox = null, ?int $size = null): ComplexRuleMessage
    {
        return new ComplexRuleMessage($headerBlock, $rawLoader, $this->intel, $mailbox, $size);
    }

    public function messageFromRaw(string $raw, ?string $mailbox = null): ComplexRuleMessage
    {
        return ComplexRuleMessage::fromRaw($raw, $this->intel, $mailbox);
    }

    /** @return ComplexRule[] enabled rules of the mailbox (own + global), cached for the run */
    public function rulesFor($mailbox): array
    {
        $key = (string)$mailbox;
        if (!isset($this->cache[$key])) {
            try {
                $this->cache[$key] = $this->em->getRepository(ComplexRule::class)->forMailbox($mailbox);
            } catch (\Throwable $e) {
                $this->cache[$key] = []; // table not migrated yet
            }
        }
        return $this->cache[$key];
    }

    public function clearRuntimeCache(): void
    {
        $this->cache = [];
    }

    /** First whitelist rule matching the message, or null. */
    public function matchWhitelist(array $rules, ComplexRuleMessage $msg): ?ComplexRule
    {
        $values = $msg->provider();
        foreach ($rules as $rule) {
            if ($rule->getAction() === ComplexRule::ACTION_WHITELIST && ComplexRuleEngine::evaluate($rule->getConditionTree(), $values)) {
                return $rule;
            }
        }
        return null;
    }

    /**
     * Every non-whitelist rule matching the message.
     *
     * @return array{score:int, spam:bool, quarantine:bool, reasons:array, hits:ComplexRule[]}
     */
    public function matchOthers(array $rules, ComplexRuleMessage $msg, bool $scoringOn = true): array
    {
        $out = ['score' => 0, 'spam' => false, 'quarantine' => false, 'reasons' => [], 'hits' => []];
        $values = $msg->provider();
        foreach ($rules as $rule) {
            $action = $rule->getAction();
            if ($action === ComplexRule::ACTION_WHITELIST || ($action === ComplexRule::ACTION_SCORE && !$scoringOn)) {
                continue;
            }
            if (!ComplexRuleEngine::evaluate($rule->getConditionTree(), $values)) {
                continue;
            }
            $score = $scoringOn && $action !== ComplexRule::ACTION_LOG ? $rule->getScore() : 0;
            $out['score'] += $score;
            $out['spam'] = $out['spam'] || $action === ComplexRule::ACTION_SPAM;
            $out['quarantine'] = $out['quarantine'] || $action === ComplexRule::ACTION_QUARANTINE;
            $out['reasons'][] = ['rule' => $rule->reasonRule(), 'score' => $score];
            $out['hits'][] = $rule;
        }
        return $out;
    }

    /** counter = counter + 1 in SQL (two scans at once must not lose hits). */
    public function countHit(ComplexRule $rule): void
    {
        if ($rule->getId() === null) {
            return;
        }
        $this->em->createQuery('UPDATE ' . ComplexRule::class . ' r SET r.counter = r.counter + 1 WHERE r.id = :id')
            ->setParameter('id', $rule->getId())
            ->execute();
    }

    /**
     * Copy validated input (panel form or plugin API JSON) onto $rule. The
     * owner is set by the caller (it decides who may own what).
     *
     * @param array{name?:mixed, enabled?:mixed, action?:mixed, score?:mixed, conditions?:mixed} $data
     * @return string[] errors (nothing changed when not empty)
     */
    public function apply(ComplexRule $rule, array $data): array
    {
        $errors = [];
        $name = trim((string)($data['name'] ?? ''));
        $action = (string)($data['action'] ?? ComplexRule::ACTION_SPAM);
        if (!isset(ComplexRuleEngine::ACTIONS[$action])) {
            $errors[] = 'Nieznana akcja reguły.';
        }
        $tree = ComplexRuleEngine::normalize($data['conditions'] ?? null, $treeErrors);
        $errors = array_merge($errors, $treeErrors);
        if ($errors) {
            return $errors;
        }
        if ($name === '') {
            $name = mb_substr(ComplexRuleEngine::describe($tree), 0, ComplexRuleEngine::MAX_NAME);
        }
        $score = array_key_exists('score', $data) && $data['score'] !== '' && $data['score'] !== null
            ? (int)$data['score'] : ComplexRuleEngine::DEFAULT_SCORES[$action];
        $rule->setName($name)
            ->setAction($action)
            ->setScore(ComplexRuleEngine::clampScore($score, $action))
            ->setEnabled(!array_key_exists('enabled', $data) || filter_var($data['enabled'], FILTER_VALIDATE_BOOLEAN))
            ->setConditionTree($tree)
            ->touch();
        return [];
    }

    /** JSON form for the plugin API, the agent export and the backup. */
    public static function toArray(ComplexRule $rule): array
    {
        return [
            'id' => $rule->getId(),
            'name' => $rule->getName(),
            'enabled' => $rule->isEnabled(),
            'action' => $rule->getAction(),
            'score' => $rule->getScore(),
            'conditions' => $rule->getConditionTree(),
            'description' => $rule->describe(),
            'global' => RuleOwnership::isGlobal($rule->getEmail()),
            'owner' => $rule->getEmail(),
            'counter' => $rule->getCounter(),
            'source' => $rule->getSource(),
            'created_by' => $rule->getCreatedBy(),
            'updated_at' => $rule->getUpdatedAt()->format(\DateTimeInterface::ATOM),
        ];
    }

    /** Fields / matches / actions for the rule builders (panel and plugin). */
    public static function vocabulary(): array
    {
        return [
            'fields' => ComplexRuleEngine::fieldList(),
            'matches' => ComplexRuleEngine::MATCHES,
            'number_matches' => ComplexRuleEngine::NUMBER_MATCHES,
            'actions' => ComplexRuleEngine::ACTIONS,
            'default_scores' => ComplexRuleEngine::DEFAULT_SCORES,
            'limits' => [
                'depth' => ComplexRuleEngine::MAX_DEPTH,
                'conditions' => ComplexRuleEngine::MAX_CONDITIONS,
                'value' => ComplexRuleEngine::MAX_VALUE,
                'score_min' => ComplexRuleEngine::SCORE_MIN,
                'score_max' => ComplexRuleEngine::SCORE_MAX,
                'per_owner' => self::MAX_PER_OWNER,
            ],
        ];
    }
}
