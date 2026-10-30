<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PatternMatcher;
use AntispamBundle\Services\RuntimeCacheInterface;
use AntispamBundle\Services\ScoringService;
use Doctrine\ORM\EntityManagerInterface;

class CheckEmailBlacklist implements RuntimeCacheInterface
{
    use SenderRuleTrait;

    private $em;
    private $ms;
    private $scoring;
    /** @var array<string, array> rules cached per account email (cleared before every background job) */
    private $rulesCache = [];

    public function __construct(EntityManagerInterface $em, MessageService $ms, ?ScoringService $scoring = null)
    {
        $this->em = $em;
        $this->ms = $ms;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        $msg = $event->getMessage();

        $from = self::fromAddress($event);
        if ($from === null) {
            return;
        }
        $email = $from[0];

        $cacheKey = (string)$event->getEmail();
        if (!isset($this->rulesCache[$cacheKey])) {
            $this->rulesCache[$cacheKey] = $this->em->getRepository(EmailBlacklist::class)
                ->findBy(['email' => \AntispamBundle\Services\RuleOwnership::scope($event->getEmail())]);
        }
        $rules = $this->rulesCache[$cacheKey];

        $match = PatternMatcher::findMatching($rules, $email, 'getBlacklistemail');
        if (!$match) {
            return;
        }

        if (!$event->isInitialScan()) {
            self::incrementCounter($this->em, $match);
        }

        if ($this->scoring && $this->scoring->isScoringEnabled()) {
            $event->setSpamscore($event->getSpamscore() + $match->getScore());
            $event->addReasons([[
                'rule' => 'email_blacklist:' . $match->getBlacklistemail() . ' (' . $match->getPatternType() . ')',
                'score' => $match->getScore(),
            ]]);
            $event->setBlacklist(true);
            $event->setSpam(true);
            return;
        }

        $this->ms->setAsChecked($msg, $event->getEmail());
        $event->setBlacklist(true);
        $event->setSpam(true);
    }

    public function clearRuntimeCache(): void
    {
        $this->rulesCache = [];
    }
}
