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

    public function __construct(EntityManagerInterface $em, ScoringService $scoring, private ?MailboxSettingsResolver $mailboxSettings = null)
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

        return $rules;
    }
}
