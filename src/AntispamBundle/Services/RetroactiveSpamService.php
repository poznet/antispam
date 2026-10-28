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
use Doctrine\ORM\EntityManagerInterface;

/**
 * Applies a newly added blacklist rule to mail that is already in INBOX:
 * matching messages from the last DAYS days are moved to SPAM (never deleted,
 * so a mistake can be undone from the spam folder).
 *
 * Cheap on purpose: IMAP lets the server search by sender (exact rules) or by
 * date (wildcard/regex), the Maildir agent only reads headers. Rules below the
 * spam threshold only add points in the scan, so they are not applied here.
 */
class RetroactiveSpamService
{
    const DAYS = 30;
    const IMAP_MAX_CANDIDATES = 500;

    public function __construct(
        private EntityManagerInterface $em,
        private ScoringService $scoring,
        private ImapScanService $imapScan,
        private ConnectionService $legacyConnection,
        private ConfigService $config,
        private InboxService $inbox,
        private SshService $ssh,
        private AgentRulesExporter $rulesExporter,
    ) {
    }

    /**
     * @param Blacklist|EmailBlacklist $rule already persisted and flushed
     *
     * @return array ['moved' => int, 'errors' => string[], 'skipped' => string|null]
     */
    public function applyRule($rule)
    {
        $result = ['moved' => 0, 'errors' => [], 'skipped' => null];
        if ($this->scoring->isScoringEnabled() && (int)$rule->getScore() < $this->scoring->getSpamThreshold()) {
            $result['skipped'] = sprintf('reguła ma %d pkt, a próg spamu to %d', $rule->getScore(), $this->scoring->getSpamThreshold());
            return $result;
        }

        $owner = (string)$rule->getEmail();
        foreach ($this->em->getRepository(Account::class)->findBy(RuleOwnership::isGlobal($owner) ? [] : ['email' => $owner]) as $account) {
            try {
                if ($account->isSsh()) {
                    $result['moved'] += $this->applySsh($account);
                } else {
                    $connection = $this->imapScan->connect($account);
                    try {
                        $result['moved'] += $this->applyImap($connection, (string)$account->getEmail(), $rule);
                    } finally {
                        $connection->close();
                    }
                }
            } catch (\Throwable $e) {
                $result['errors'][] = $account->getEmail() . ': ' . $e->getMessage();
            }
        }

        if ($this->imapScan->isLegacyConfigured() && (RuleOwnership::isGlobal($owner) || strcasecmp((string)$this->config->get('email'), $owner) === 0)) {
            try {
                $result['moved'] += $this->applyImap($this->legacyConnection->getConnection(), (string)$this->config->get('email'), $rule);
            } catch (\Throwable $e) {
                $result['errors'][] = 'IMAP: ' . $e->getMessage();
            }
        }

        return $result;
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

    private function applySsh(Account $account)
    {
        if (!$account->getAgentDeployed()) {
            return 0;
        }
        // The agent only knows rules pushed to it - send the new one first.
        $sync = $this->ssh->syncRules($account, json_encode($this->rulesExporter->export($account->getEmail())));
        if (isset($sync['success']) && !$sync['success']) {
            throw new \RuntimeException('synchronizacja reguł nie powiodła się');
        }
        $res = $this->ssh->applyBlacklist($account, $this->scoring->getSpamThreshold(), self::DAYS);
        if (!isset($res['moved_to_spam'])) {
            throw new \RuntimeException('agent nie obsługuje tej operacji - wdróż go ponownie (Konta → Wdróż)');
        }
        return (int)$res['moved_to_spam'];
    }

    /** @param Blacklist|EmailBlacklist $rule */
    private function applyImap(ConnectionInterface $connection, $owner, $rule)
    {
        $isDomain = $rule instanceof Blacklist;
        $pattern = strtolower((string)($isDomain ? $rule->getHost() : $rule->getBlacklistemail()));
        $type = $rule->getPatternType() ?: PatternMatcher::EXACT;

        // Exact rules: let the server find the sender (substring match, verified below).
        $search = $type === PatternMatcher::EXACT
            ? new From($isDomain ? '@' . $pattern : $pattern)
            : new Since(new \DateTimeImmutable('-' . self::DAYS . ' days'));

        $whitelist = $this->em->getRepository(Whitelist::class)->findBy(['email' => RuleOwnership::scope($owner)]);
        $emailWhitelist = $this->em->getRepository(EmailWhitelist::class)->findBy(['email' => RuleOwnership::scope($owner)]);
        $spam = $this->inbox->getSpamFolder($connection);

        $moved = 0;
        $seen = 0;
        foreach ($connection->getMailbox('INBOX')->getMessages($search) as $msg) {
            if (++$seen > self::IMAP_MAX_CANDIDATES) {
                break;
            }
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
        }

        if ($moved > 0) {
            $connection->expunge();
        }
        return $moved;
    }
}
