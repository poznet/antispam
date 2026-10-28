<?php

namespace AntispamBundle\Services\Bayes;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BayesMessage;
use AntispamBundle\Entity\BayesToken;
use AntispamBundle\Services\ConfigService;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * Optional local learned classifier (naive Bayes, Robinson / chi-square;
 * docs/bayes.md). Off by default (bayes.enabled).
 *
 *   - learn*(): a user verdict (plugin report, phishing report, quarantine
 *     release / delete, SPAM release, antispam:bayes:train) adds the
 *     message's token hashes to the global scope and, with
 *     bayes.per_mailbox, to the mailbox's own scope. A message learned again
 *     with the other verdict is unlearned first; the same verdict twice is a
 *     no-op.
 *   - score*(): spam probability of a message -> points, only once the scope
 *     has at least bayes.min_spam spam and bayes.min_ham ham messages.
 *
 * Training never fails the caller: errors are logged and reported as
 * ['learned' => false].
 */
class BayesService
{
    public const DEFAULT_MIN_SPAM = 50;
    public const DEFAULT_MIN_HAM = 50;
    public const DEFAULT_SPAM_SCORE = 5;
    public const DEFAULT_LIKELY_SCORE = 3;
    public const DEFAULT_HAM_SCORE = 2;
    public const DEFAULT_AGENT_MAX_TOKENS = 20000;
    public const MAX_AGENT_TOKENS = 50000;
    public const DEFAULT_MESSAGE_RETENTION_DAYS = 365;
    public const DEFAULT_TOKEN_RETENTION_DAYS = 180;
    /** Messages above this size are not fetched for training (quarantine / SPAM release). */
    public const MAX_TRAIN_BYTES = 2097152;

    /** @var array<string, int> mailbox e-mail => account id (0 = none) */
    private array $scopeCache = [];

    public function __construct(
        private BayesStore $store,
        private ConfigService $config,
        private EntityManagerInterface $em,
        private ?LoggerInterface $logger = null,
    ) {
    }

    // --- settings ---------------------------------------------------------

    public function isEnabled(): bool
    {
        return $this->bool('bayes.enabled', false);
    }

    /** Also keep a separate token table per mailbox (scored when it has enough training itself). */
    public function isPerMailbox(): bool
    {
        return $this->bool('bayes.per_mailbox', false);
    }

    public function getMinSpam(): int
    {
        return max(1, $this->int('bayes.min_spam', self::DEFAULT_MIN_SPAM));
    }

    public function getMinHam(): int
    {
        return max(1, $this->int('bayes.min_ham', self::DEFAULT_MIN_HAM));
    }

    /** @return array{spam_score:int, likely_score:int, ham_score:int} */
    public function getWeights(): array
    {
        return [
            'spam_score' => max(0, $this->int('bayes.spam_score', self::DEFAULT_SPAM_SCORE)),
            'likely_score' => max(0, $this->int('bayes.likely_score', self::DEFAULT_LIKELY_SCORE)),
            'ham_score' => max(0, $this->int('bayes.ham_score', self::DEFAULT_HAM_SCORE)),
        ];
    }

    public function getAgentMaxTokens(): int
    {
        return min(self::MAX_AGENT_TOKENS, max(0, $this->int('bayes.agent_max_tokens', self::DEFAULT_AGENT_MAX_TOKENS)));
    }

    // --- learning ---------------------------------------------------------

    /**
     * @param string      $verdict spam | ham
     * @param string|null $mailbox e-mail of the mailbox the verdict belongs to (per-mailbox scope)
     *
     * @return array{learned:bool, reason?:string, tokens?:int, reversed?:bool}
     */
    public function learnRaw(string $raw, string $verdict, ?string $mailbox = null, string $source = 'manual'): array
    {
        if (!$this->isEnabled()) {
            return ['learned' => false, 'reason' => 'disabled'];
        }
        try {
            return $this->learnFields(BayesTokenizer::fieldsFromRaw($raw), $verdict, $mailbox, $source);
        } catch (\Throwable $e) {
            return $this->failed($e);
        }
    }

    /** IMAP message (quarantine / SPAM release, bootstrap command): read before it is moved. */
    public function learnImap($message, string $verdict, ?string $mailbox = null, string $source = 'manual'): array
    {
        if (!$this->isEnabled()) {
            return ['learned' => false, 'reason' => 'disabled'];
        }
        try {
            try {
                $size = (int)$message->getSize();
            } catch (\Throwable $e) {
                $size = 0;
            }
            if ($size > self::MAX_TRAIN_BYTES) {
                return ['learned' => false, 'reason' => 'too_large'];
            }
            return $this->learnFields(BayesTokenizer::fieldsFromImap($message), $verdict, $mailbox, $source);
        } catch (\Throwable $e) {
            return $this->failed($e);
        }
    }

    /** Learn already-extracted fields (BayesTokenizer::fieldsFrom*()); works whether or not the classifier is enabled. */
    public function learnFields(array $fields, string $verdict, ?string $mailbox = null, string $source = 'manual'): array
    {
        if (!in_array($verdict, [BayesMessage::SPAM, BayesMessage::HAM], true)) {
            throw new \InvalidArgumentException('Unknown verdict: ' . $verdict);
        }
        $hexes = BayesTokenizer::hashes(BayesTokenizer::tokenize($fields));
        if (count($hexes) < 3) {
            return ['learned' => false, 'reason' => 'empty'];
        }
        $fingerprint = self::fingerprint($fields, $hexes);
        $result = ['learned' => false, 'tokens' => count($hexes), 'reversed' => false, 'reason' => 'duplicate'];

        foreach ($this->scopesFor($mailbox) as $scope) {
            $previous = $this->store->learnedVerdict($scope, $fingerprint);
            if ($previous === $verdict) {
                continue;
            }
            if ($previous !== null) {
                $this->store->apply($scope, $hexes, $previous, -1);
                $result['reversed'] = true;
            }
            $this->store->apply($scope, $hexes, $verdict, 1);
            $this->store->rememberMessage($scope, $fingerprint, $verdict, substr($source, 0, 24));
            $result['learned'] = true;
            unset($result['reason']);
        }

        return $result;
    }

    // --- scoring ----------------------------------------------------------

    /**
     * @return array{ready:bool, p:?float, scope:int, spam:int, ham:int}
     */
    public function classifyFields(array $fields, ?string $mailbox = null): array
    {
        $scope = BayesToken::GLOBAL_SCOPE;
        $totals = null;
        if ($this->isPerMailbox() && ($own = $this->scopeOf($mailbox)) > 0) {
            $t = $this->store->totals($own);
            if ($this->isTrained($t)) {
                [$scope, $totals] = [$own, $t];
            }
        }
        $totals ??= $this->store->totals($scope);
        $out = ['ready' => $this->isTrained($totals), 'p' => null, 'scope' => $scope, 'spam' => $totals['spam'], 'ham' => $totals['ham']];
        if (!$out['ready']) {
            return $out;
        }

        $hexes = BayesTokenizer::hashes(BayesTokenizer::tokenize($fields));
        $probs = [];
        foreach ($this->store->counts($scope, $hexes) as $hex => [$spam, $ham]) {
            $probs[$hex] = BayesMath::tokenProb($spam, $ham, $totals['spam'], $totals['ham']);
        }
        $out['p'] = BayesMath::combine($probs);

        return $out;
    }

    /**
     * Points for the pipeline / plugin scanner (0 and no reason when disabled,
     * untrained or undecided).
     *
     * @return array{score:int, reason:?array{rule:string, score:int}, p:?float}
     */
    public function scoreFields(array $fields, ?string $mailbox = null, bool $blacklisted = false): array
    {
        if (!$this->isEnabled()) {
            return ['score' => 0, 'reason' => null, 'p' => null];
        }
        try {
            $c = $this->classifyFields($fields, $mailbox);
        } catch (\Throwable $e) {
            $this->logger?->warning('Bayes scoring failed: {error}', ['error' => $e->getMessage()]);
            return ['score' => 0, 'reason' => null, 'p' => null];
        }
        if ($c['p'] === null) {
            return ['score' => 0, 'reason' => null, 'p' => null];
        }

        return BayesMath::scoreFor($c['p'], $this->getWeights(), $blacklisted) + ['p' => $c['p']];
    }

    // --- agent export -----------------------------------------------------

    /**
     * Compact token table for a Maildir agent: the most frequent tokens of
     * the scope it would be scored with, as [hash, probability] (6 decimals),
     * only strong ones (|p - 0.5| >= 0.1). Empty when disabled or untrained.
     *
     * @return array{enabled:bool, scope:int, spam:int, ham:int, tokens:array<int, array{0:string, 1:float}>}
     */
    public function exportForAgent(?string $mailbox): array
    {
        $out = ['enabled' => false, 'scope' => 0, 'spam' => 0, 'ham' => 0, 'tokens' => []];
        if (!$this->isEnabled()) {
            return $out;
        }
        $scope = BayesToken::GLOBAL_SCOPE;
        $totals = $this->store->totals($scope);
        if ($this->isPerMailbox() && ($own = $this->scopeOf($mailbox)) > 0 && $this->isTrained($t = $this->store->totals($own))) {
            [$scope, $totals] = [$own, $t];
        }
        $out = ['enabled' => $this->isTrained($totals), 'scope' => $scope, 'spam' => $totals['spam'], 'ham' => $totals['ham'], 'tokens' => []];
        if (!$out['enabled']) {
            return $out;
        }
        $max = $this->getAgentMaxTokens();
        // Read more than needed: weak tokens (p near 0.5) are dropped.
        foreach ($this->store->topTokens($scope, $max * 2) as [$hex, $spam, $ham]) {
            $p = BayesMath::tokenProb($spam, $ham, $totals['spam'], $totals['ham']);
            if (abs($p - 0.5) >= BayesMath::MIN_STRENGTH) {
                $out['tokens'][] = [$hex, round($p, 6)];
                if (count($out['tokens']) >= $max) {
                    break;
                }
            }
        }
        return $out;
    }

    // --- maintenance ------------------------------------------------------

    public function stats(): array
    {
        $s = $this->store->stats();
        $s['ready'] = $this->isTrained(['spam' => $s['spam'], 'ham' => $s['ham']]);
        $s['min_spam'] = $this->getMinSpam();
        $s['min_ham'] = $this->getMinHam();
        return $s;
    }

    public function reset(): int
    {
        $this->scopeCache = [];
        return $this->store->reset();
    }

    /** @return array{messages:int, tokens:int, orphans:int} */
    public function purge(): array
    {
        $ids = array_map('intval', array_column(
            $this->em->getConnection()->fetchAllAssociative('SELECT id FROM antispam_account'),
            'id'
        ));
        return $this->store->purge(
            max(0, $this->int('bayes.message_retention_days', self::DEFAULT_MESSAGE_RETENTION_DAYS)),
            max(0, $this->int('bayes.token_retention_days', self::DEFAULT_TOKEN_RETENTION_DAYS)),
            $ids,
        );
    }

    // --- helpers ----------------------------------------------------------

    /** @param array{spam:int, ham:int} $totals */
    private function isTrained(array $totals): bool
    {
        return $totals['spam'] >= $this->getMinSpam() && $totals['ham'] >= $this->getMinHam();
    }

    /** @return int[] global, plus the mailbox's own scope with bayes.per_mailbox */
    private function scopesFor(?string $mailbox): array
    {
        $scopes = [BayesToken::GLOBAL_SCOPE];
        if ($this->isPerMailbox() && ($own = $this->scopeOf($mailbox)) > 0) {
            $scopes[] = $own;
        }
        return $scopes;
    }

    /** Account id of a mailbox address (first by id, like MailboxSettingsResolver), 0 = none / legacy mailbox. */
    public function scopeOf(?string $mailbox): int
    {
        $mailbox = strtolower(trim((string)$mailbox));
        if ($mailbox === '') {
            return 0;
        }
        if (!array_key_exists($mailbox, $this->scopeCache)) {
            $account = $this->em->getRepository(Account::class)->findOneBy(['email' => $mailbox], ['id' => 'ASC']);
            $this->scopeCache[$mailbox] = $account instanceof Account ? (int)$account->getId() : 0;
        }
        return $this->scopeCache[$mailbox];
    }

    /** SHA-1 of the Message-ID, or of the sorted token hashes for mail without one. */
    public static function fingerprint(array $fields, array $hexes): string
    {
        $id = strtolower(trim((string)($fields['message_id'] ?? ''), " \t<>"));
        if ($id !== '') {
            return sha1('mid:' . $id);
        }
        sort($hexes);
        return sha1('tok:' . implode(',', $hexes));
    }

    private function failed(\Throwable $e): array
    {
        $this->logger?->warning('Bayes training failed: {error}', ['error' => $e->getMessage(), 'exception' => $e]);
        return ['learned' => false, 'reason' => 'error'];
    }

    private function int(string $key, int $default): int
    {
        $v = $this->config->get($key);
        return ($v === null || $v === '' || !is_numeric($v)) ? $default : (int)$v;
    }

    private function bool(string $key, bool $default): bool
    {
        $v = $this->config->get($key);
        if ($v === null || $v === '') {
            return $default;
        }
        return $v === true || in_array(strtolower((string)$v), ['1', 'true', 'yes', 'on'], true);
    }
}
