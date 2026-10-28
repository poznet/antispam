<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Builds the rules.json payload pushed to a Maildir agent by
 * `antispam:agent:sync` and the "Sync" button on the accounts page.
 */
class AgentRulesExporter
{
    private $em;
    private $scoring;

    public function __construct(EntityManagerInterface $em, ScoringService $scoring, private ?MailboxSettingsResolver $mailboxSettings = null, private ?Bayes\BayesService $bayes = null)
    {
        $this->em = $em;
        $this->scoring = $scoring;
    }

    /**
     * @param Account|null $account the agent's account: its thresholds /
     *        scoring switch go into `settings` (override -> global); null =
     *        looked up by e-mail
     */
    public function export($email, ?Account $account = null)
    {
        $rules = [
            'whitelist' => [],
            'email_whitelist' => [],
            'blacklist' => [],
            'email_blacklist' => [],
            'dnsbl' => [],
        ];

        foreach ($this->em->getRepository(Whitelist::class)->findBy(['email' => RuleOwnership::scope($email)]) as $item) {
            $rules['whitelist'][] = [
                'email' => $item->getEmail(),
                'host' => $item->getHost(),
                'pattern_type' => $item->getPatternType(),
            ];
        }
        foreach ($this->em->getRepository(EmailWhitelist::class)->findBy(['email' => RuleOwnership::scope($email)]) as $item) {
            $rules['email_whitelist'][] = [
                'email' => $item->getEmail(),
                'whitelistemail' => $item->getWhitelistemail(),
                'pattern_type' => $item->getPatternType(),
            ];
        }
        foreach ($this->em->getRepository(Blacklist::class)->findBy(['email' => RuleOwnership::scope($email)]) as $item) {
            $rules['blacklist'][] = [
                'email' => $item->getEmail(),
                'host' => $item->getHost(),
                'pattern_type' => $item->getPatternType(),
                'score' => $item->getScore(),
            ];
        }
        foreach ($this->em->getRepository(EmailBlacklist::class)->findBy(['email' => RuleOwnership::scope($email)]) as $item) {
            $rules['email_blacklist'][] = [
                'email' => $item->getEmail(),
                'blacklistemail' => $item->getBlacklistemail(),
                'pattern_type' => $item->getPatternType(),
                'score' => $item->getScore(),
            ];
        }
        foreach ($this->em->getRepository(DnsblProvider::class)->findAll() as $prov) {
            $rules['dnsbl'][] = [
                'name' => $prov->getName(),
                'zone' => $prov->getZone(),
                'score' => $prov->getScore(),
                'enabled' => $prov->isEnabled(),
                'cache_ttl' => $prov->getCacheTtl(),
            ];
        }
        $rules['settings'] = $this->mailboxSettings
            ? $this->mailboxSettings->within(
                $account ? $this->mailboxSettings->forAccount($account) : $this->mailboxSettings->forEmail($email),
                fn () => $this->scoring->exportAgentSettings($email)
            )
            : $this->scoring->exportAgentSettings($email);

        // Bayes classifier (docs/bayes.md): token probabilities of the scope
        // the mailbox is scored with, capped at bayes.agent_max_tokens. An
        // empty list (disabled / untrained) clears the agent's table.
        if ($this->bayes) {
            try {
                $bayes = $this->bayes->exportForAgent($email);
            } catch (\Throwable $e) {
                $bayes = ['enabled' => false, 'spam' => 0, 'ham' => 0, 'tokens' => []]; // tables not migrated yet
            }
            $weights = $this->bayes->getWeights();
            $rules['settings'] += [
                'bayes_enabled' => $bayes['enabled'] && $bayes['tokens'] !== [],
                'bayes_spam_score' => $weights['spam_score'],
                'bayes_likely_score' => $weights['likely_score'],
                'bayes_ham_score' => $weights['ham_score'],
                'bayes_trained_spam' => $bayes['spam'],
                'bayes_trained_ham' => $bayes['ham'],
            ];
            $rules['bayes_tokens'] = $bayes['tokens'];
        }

        return $rules;
    }
}
