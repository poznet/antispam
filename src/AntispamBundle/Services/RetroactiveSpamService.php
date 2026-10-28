<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\Whitelist;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\Search\Date\Since;
use Ddeboer\Imap\Search\Email\From;
use Ddeboer\Imap\SearchExpression;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Applies a newly added blacklist rule to mail that is already in INBOX:
 * matching messages from the last DAYS days are moved to SPAM (never deleted,
 * so a mistake can be undone from the spam folder).
 *
 * Cheap on purpose: IMAP lets the server search by date (and by sender for
 * exact rules), newest mail first, capped per rule; the Maildir agent only
 * reads headers. Rules below the
 * spam threshold only add points in the scan, so they are not applied here.
 */
class RetroactiveSpamService
{
    const DAYS = 30;
    /** Wildcard/regex rules: at most this many messages of the window are inspected. */
    const IMAP_MAX_CANDIDATES = 2000;
    /** At most this many messages are moved per rule and mailbox. */
    const IMAP_MAX_MOVES = 500;

    public function __construct(
        private EntityManagerInterface $em,
        private ScoringService $scoring,
        private ImapScanService $imapScan,
        private ConnectionService $legacyConnection,
        private ConfigService $config,
        private InboxService $inbox,
        private SshService $ssh,
        private AgentRulesExporter $rulesExporter,
        private ?MailboxSettingsResolver $mailboxSettings = null,
    ) {
    }

    /** Effective settings of the mailbox (account override -> global); null account = legacy mailbox. */
    private function settingsFor(?Account $account): MailboxSettings
    {
        if ($this->mailboxSettings) {
            return $this->mailboxSettings->forAccount($account);
        }
        return new MailboxSettings((int)$this->scoring->getSpamThreshold(), (int)$this->scoring->getQuarantineThreshold(), (bool)$this->scoring->isScoringEnabled(), false, false, null, null);
    }

    /** With scoring on, a rule below the mailbox's spam threshold only adds points in the scan. */
    private static function tooWeak($rule, MailboxSettings $settings): bool
    {
        return $settings->scoringEnabled && (int)$rule->getScore() < $settings->spamThreshold;
    }

    /**
     * @param Blacklist|EmailBlacklist $rule already persisted and flushed
     *
     * @return array ['moved' => int, 'errors' => string[], 'skipped' => string|null]
     */
    public function applyRule($rule)
    {
        $result = ['moved' => 0, 'errors' => [], 'skipped' => null];
        // The threshold is per mailbox (Ustawienia skrzynki): a rule strong
        // enough for one mailbox may only add points in another.
        $weak = [];
        $applied = 0;

        $owner = (string)$rule->getEmail();
        foreach ($this->em->getRepository(Account::class)->findBy(RuleOwnership::isGlobal($owner) ? [] : ['email' => $owner]) as $account) {
            $settings = $this->settingsFor($account);
            if (self::tooWeak($rule, $settings)) {
                $weak[] = [(string)$account->getEmail(), $settings->spamThreshold];
                continue;
            }
            $applied++;
            try {
                if ($account->isSsh()) {
                    $result['moved'] += $this->applySsh($account, $settings);
                } else {
                    $connection = $this->imapScan->connect($account);
                    try {
                        $result['moved'] += $this->applyImap($connection, (string)$account->getEmail(), $rule, $result['errors']);
                    } finally {
                        $connection->close();
                    }
                }
            } catch (\Throwable $e) {
                $result['errors'][] = $account->getEmail() . ': ' . $e->getMessage();
            }
        }

        if ($this->imapScan->isLegacyConfigured() && (RuleOwnership::isGlobal($owner) || strcasecmp((string)$this->config->get('email'), $owner) === 0)) {
            $settings = $this->settingsFor(null);
            if (self::tooWeak($rule, $settings)) {
                $weak[] = [(string)$this->config->get('email'), $settings->spamThreshold];
            } else {
                $applied++;
                try {
                    $result['moved'] += $this->applyImap($this->legacyConnection->getConnection(), (string)$this->config->get('email'), $rule, $result['errors']);
                } catch (\Throwable $e) {
                    $result['errors'][] = 'IMAP: ' . $e->getMessage();
                }
            }
        }

        $result['skipped'] = $this->skippedReason($rule, $weak, $applied);

        return $result;
    }

    /**
     * @param array<int, array{0: string, 1: int}> $weak mailboxes (e-mail, spam threshold) the rule is too weak for
     */
    private function skippedReason($rule, array $weak, int $applied): ?string
    {
        $global = $this->settingsFor(null);
        if (!$weak) {
            // Nothing to check at all: still say why when the rule is too weak globally.
            return $applied === 0 && self::tooWeak($rule, $global)
                ? sprintf('reguła ma %d pkt, a próg spamu to %d', $rule->getScore(), $global->spamThreshold)
                : null;
        }
        $thresholds = array_unique(array_column($weak, 1));
        if ($applied === 0 && count($thresholds) === 1) {
            return sprintf('reguła ma %d pkt, a próg spamu to %d', $rule->getScore(), reset($thresholds));
        }
        return sprintf('reguła ma %d pkt, a próg spamu skrzynki jest wyższy: %s', $rule->getScore(), implode(', ', array_map(
            static fn ($w) => sprintf('%s (%d)', $w[0], $w[1]),
            array_slice($weak, 0, 10)
        )) . (count($weak) > 10 ? sprintf(' i %d innych', count($weak) - 10) : ''));
    }

    /** Short Polish summary for a flash message, or null when nothing worth saying happened. */
    public static function describe(array $result)
    {
        $parts = [];
        if ($result['moved'] > 0) {
            $parts[] = sprintf('Przeniesiono do SPAM %d wiadomości, które już były w skrzynce.', $result['moved']);
        }
        if ($result['skipped']) {
            $parts[] = 'Istniejących wiadomości nie przeniesiono: ' . $result['skipped'] . '.';
        }
        if ($result['errors']) {
            $parts[] = 'Nie udało się sprawdzić skrzynki: ' . implode('; ', $result['errors']);
        }
        return $parts ? implode(' ', $parts) : null;
    }

    private function applySsh(Account $account, MailboxSettings $settings)
    {
        if (!$account->getAgentDeployed()) {
            return 0;
        }
        // The agent only knows rules pushed to it - send the new one first.
        $sync = $this->ssh->syncRules($account, json_encode($this->rulesExporter->export($account->getEmail(), $account)));
        if (isset($sync['success']) && !$sync['success']) {
            throw new \RuntimeException('synchronizacja reguł nie powiodła się');
        }
        $res = $this->ssh->applyBlacklist($account, $settings->spamThreshold, self::DAYS);
        if (!isset($res['moved_to_spam'])) {
            throw new \RuntimeException('agent nie obsługuje tej operacji - wdróż go ponownie (Konta → Wdróż)');
        }
        return (int)$res['moved_to_spam'];
    }

    /**
     * @param Blacklist|EmailBlacklist $rule
     * @param string[] $errors per-message problems are appended here
     */
    private function applyImap(ConnectionInterface $connection, $owner, $rule, array &$errors = [])
    {
        $isDomain = $rule instanceof Blacklist;
        $pattern = strtolower((string)($isDomain ? $rule->getHost() : $rule->getBlacklistemail()));
        $type = $rule->getPatternType() ?: PatternMatcher::EXACT;

        // Same window for every rule type (docs: "the last 30 days"). Exact
        // rules also let the server pre-filter by sender (substring match,
        // verified below) - unless the value cannot be put in a quoted IMAP
        // string, then the date window alone is searched.
        $search = (new SearchExpression())->addCondition(new Since(new \DateTimeImmutable('-' . self::DAYS . ' days')));
        $serverFiltered = $type === PatternMatcher::EXACT && preg_match('/^[\x21\x23-\x5b\x5d-\x7e]+$/', $pattern);
        if ($serverFiltered) {
            $search->addCondition(new From($isDomain ? '@' . $pattern : $pattern));
        }

        $whitelist = $this->em->getRepository(Whitelist::class)->findBy(['email' => RuleOwnership::scope($owner)]);
        $emailWhitelist = $this->em->getRepository(EmailWhitelist::class)->findBy(['email' => RuleOwnership::scope($owner)]);
        $spam = $this->inbox->getSpamFolder($connection);
        $inbox = $connection->getMailbox('INBOX');

        // Newest first, so the caps cut off the oldest mail, not today's.
        $uids = array_map('intval', $inbox->getMessages($search)->getArrayCopy());
        rsort($uids, SORT_NUMERIC);

        $moved = 0;
        $seen = 0;
        foreach ($uids as $uid) {
            if ($moved >= self::IMAP_MAX_MOVES || (!$serverFiltered && ++$seen > self::IMAP_MAX_CANDIDATES)) {
                break;
            }
            try {
                $msg = $inbox->getMessage($uid);
                $from = $msg->getFrom();
                $sender = $from ? strtolower((string)$from->getAddress()) : '';
                $host = substr(strrchr($sender, '@') ?: '', 1);
                if ($sender === '' || PatternMatcher::match($pattern, $isDomain ? $host : $sender, $type) === false) {
                    continue;
                }
                if (PatternMatcher::findMatching($whitelist, $host, 'getHost')
                    || PatternMatcher::findMatching($emailWhitelist, $sender, 'getWhitelistemail')) {
                    continue;
                }

                $subject = (string)$msg->getSubject();
                $msg->move($spam);
                $moved++;
                $this->scoring->logDecision($owner, $rule->getScore(), SpamScoreLog::DECISION_SPAM, [[
                    'rule' => 'retroactive ' . ($isDomain ? 'blacklist:' : 'email_blacklist:') . $pattern,
                    'score' => (int)$rule->getScore(),
                ]], $sender, $subject, SpamScoreLog::SOURCE_RETRO, SpamScoreLog::OUTCOME_SPAM_FOLDER);
            } catch (\Throwable $e) {
                if (count($errors) < 10) {
                    $errors[] = 'UID ' . $uid . ': ' . $e->getMessage();
                }
            }
        }

        if ($moved > 0) {
            $connection->expunge();
        }
        return $moved;
    }
}
