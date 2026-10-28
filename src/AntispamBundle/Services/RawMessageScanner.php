<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\Whitelist;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Scores a raw RFC 822 message (as submitted by the Thunderbird plugin) with
 * the same rules as the IMAP event pipeline: domain/e-mail whitelists and
 * blacklists of the account, header heuristics, impersonation, DNSBL, link
 * protection, the shared spam feed, the CERT Polska domain list and the attachment policy. The result is logged to SpamScoreLog like any other scan, but the
 * message itself is never moved here — the plugin acts on the decision
 * inside the user's mail client.
 */
class RawMessageScanner
{
    private $em;
    private $headers;
    private $dnsbl;
    private $scoring;
    private $feed;
    private $impersonation;
    private $urls;
    private $attachments;
    private $cert;

    public function __construct(
        EntityManagerInterface $em,
        HeaderAnalyzer $headers,
        DnsblService $dnsbl,
        ScoringService $scoring,
        SpamSignalService $feed,
        ImpersonationAnalyzer $impersonation,
        UrlAnalyzer $urls,
        AttachmentPolicyAnalyzer $attachments,
        CertHoleService $cert
    ) {
        $this->em = $em;
        $this->headers = $headers;
        $this->dnsbl = $dnsbl;
        $this->scoring = $scoring;
        $this->feed = $feed;
        $this->impersonation = $impersonation;
        $this->urls = $urls;
        $this->attachments = $attachments;
        $this->cert = $cert;
    }

    /**
     * @param string $raw          full message source
     * @param string $accountEmail mailbox whose rules apply
     *
     * @return array{decision:string, spam:bool, score:int, spam_threshold:int, quarantine_threshold:int, reasons:array, sender:string, subject:string}
     */
    public function scan($raw, $accountEmail)
    {
        $msg = new RawMessageParser($raw);
        $sender = $msg->getFromAddress();
        $host = $msg->getFromHost();
        $subject = $msg->getSubject();

        $score = 0;
        $reasons = [];
        $forcedSpam = false;
        $whitelisted = false;
        $scoringOn = $this->scoring->isScoringEnabled();

        // Whitelists short-circuit, exactly like CheckWhitelist / CheckEmailWhitelist.
        if ($host && ($rule = $this->matchRule(Whitelist::class, $accountEmail, $host, 'getHost'))) {
            $whitelisted = true;
            $reasons[] = ['rule' => 'whitelist:' . $rule->getHost(), 'score' => 0];
        } elseif ($sender && ($rule = $this->matchRule(EmailWhitelist::class, $accountEmail, $sender, 'getWhitelistemail'))) {
            $whitelisted = true;
            $reasons[] = ['rule' => 'email_whitelist:' . $rule->getWhitelistemail(), 'score' => 0];
        }

        if (!$whitelisted) {
            if ($host && ($rule = $this->matchRule(Blacklist::class, $accountEmail, $host, 'getHost'))) {
                $score += $rule->getScore();
                $reasons[] = ['rule' => 'blacklist:' . $rule->getHost() . ' (' . $rule->getPatternType() . ')', 'score' => $rule->getScore()];
                $forcedSpam = $forcedSpam || !$scoringOn;
            }
            if ($sender && ($rule = $this->matchRule(EmailBlacklist::class, $accountEmail, $sender, 'getBlacklistemail'))) {
                $score += $rule->getScore();
                $reasons[] = ['rule' => 'email_blacklist:' . $rule->getBlacklistemail() . ' (' . $rule->getPatternType() . ')', 'score' => $rule->getScore()];
                $forcedSpam = $forcedSpam || !$scoringOn;
            }
        }

        if (!$whitelisted && $scoringOn) {
            if ($this->scoring->isHeaderCheckEnabled()) {
                try {
                    $analysis = $this->headers->analyzeRaw($msg->getHeaderBlock());
                    $score += $analysis['score'];
                    $reasons = array_merge($reasons, $analysis['reasons']);
                } catch (\Throwable $e) {}
            }

            if ($this->scoring->isImpersonationEnabled()) {
                try {
                    $result = $this->impersonation->analyze(
                        ['from_name' => $msg->getFromName(), 'from_email' => $sender, 'auth_results' => HeaderAnalyzer::topmostAuthResults($msg->getHeaderBlock())],
                        $this->scoring->getProtectedDomains($accountEmail),
                        ImpersonationAnalyzer::parseVips($this->scoring->getVipList()),
                        $this->scoring->getImpersonationScores()
                    );
                    $score += $result['score'];
                    $reasons = array_merge($reasons, $result['reasons']);
                } catch (\Throwable $e) {}
            }

            if ($this->scoring->isDnsblEnabled() && ($ip = $msg->getConnectingIp())) {
                try {
                    $dnsblReasons = [];
                    $score += $this->dnsbl->scoreForIp($ip, $dnsblReasons);
                    $reasons = array_merge($reasons, $dnsblReasons);
                } catch (\Throwable $e) {}
            }

            $parts = null;
            if ($this->scoring->isUrlCheckEnabled()) {
                try {
                    $parts = $msg->getParts();
                    $result = $this->urls->analyze($parts['html'], $parts['text'], $this->scoring->getUrlConfig());
                    $score += $result['score'];
                    $reasons = array_merge($reasons, $result['reasons']);
                } catch (\Throwable $e) {}
            }

            if ($this->scoring->isAttachmentPolicyEnabled()) {
                try {
                    $parts = $parts ?: $msg->getParts();
                    if ($parts['attachments']) {
                        $result = $this->attachments->analyze($parts['attachments'], $this->scoring->getAttachmentPolicyConfig());
                        $score += $result['score'];
                        $reasons = array_merge($reasons, $result['reasons']);
                    }
                } catch (\Throwable $e) {}
            }

            if ($this->cert->isEnabled()) {
                try {
                    $parts = $parts ?: $msg->getParts();
                    $senders = array_merge(
                        [$host],
                        CertHoleService::hostsFromAddressHeader($msg->getHeader('reply-to')),
                        CertHoleService::hostsFromAddressHeader($msg->getHeader('return-path'))
                    );
                    $result = $this->cert->analyze(
                        array_values(array_filter($senders)),
                        CertHoleService::linkHosts($parts['html'], $parts['text']),
                        $this->scoring->getSpamThreshold()
                    );
                    $score += $result['score'];
                    $reasons = array_merge($reasons, $result['reasons']);
                } catch (\Throwable $e) {}
            }

            if ($this->feed->isEnabled()) {
                try {
                    $matchScore = $this->feed->getMatchScore();
                    foreach ($this->feed->matchSignals($this->feed->signalsFor($sender, $msg->getBodyText())) as $hit) {
                        $score += $matchScore;
                        $reasons[] = ['rule' => 'shared_feed:' . $hit['type'] . ' (reports=' . $hit['reports'] . ')', 'score' => $matchScore];
                    }
                } catch (\Throwable $e) {}
            }
        }

        $decision = $this->scoring->classify($score, $forcedSpam, $whitelisted);
        $reasons[] = ['rule' => 'source:thunderbird_plugin', 'score' => 0];
        $this->scoring->logDecision($accountEmail, $score, $decision, $reasons, $sender, $subject, SpamScoreLog::SOURCE_PLUGIN, SpamScoreLog::OUTCOME_NONE);

        return [
            'decision' => $decision,
            'spam' => $decision === SpamScoreLog::DECISION_SPAM,
            'score' => $score,
            'spam_threshold' => $this->scoring->getSpamThreshold(),
            'quarantine_threshold' => $this->scoring->getQuarantineThreshold(),
            'reasons' => $reasons,
            'sender' => $sender,
            'subject' => $subject,
        ];
    }

    /** First matching rule of the account (hit counter bumped), or null. */
    private function matchRule($entity, $accountEmail, $value, $getter)
    {
        $rules = $this->em->getRepository($entity)->findBy(['email' => RuleOwnership::scope($accountEmail)]);
        $match = PatternMatcher::findMatching($rules, $value, $getter);
        if ($match) {
            $match->setCounter($match->getCounter() + 1);
            $this->em->flush();
        }
        return $match;
    }
}
