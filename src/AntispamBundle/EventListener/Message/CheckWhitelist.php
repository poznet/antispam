<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PatternMatcher;
use AntispamBundle\Services\RuntimeCacheInterface;
use Doctrine\ORM\EntityManagerInterface;

class CheckWhitelist implements RuntimeCacheInterface
{
    use SenderRuleTrait;

    private $em;
    private $ms;
    /** @var array<string, array> rules cached per account email (cleared before every background job) */
    private $rulesCache = [];

    public function __construct(EntityManagerInterface $em, MessageService $ms)
    {
        $this->em = $em;
        $this->ms = $ms;
    }

    public function check(MessageEvent $event)
    {
        $msg = $event->getMessage();

        $from = self::fromAddress($event);
        if ($from === null) {
            return;
        }
        $host = $from[1];

        $cacheKey = (string)$event->getEmail();
        if (!isset($this->rulesCache[$cacheKey])) {
            $this->rulesCache[$cacheKey] = $this->em->getRepository(Whitelist::class)
                ->findBy(['email' => \AntispamBundle\Services\RuleOwnership::scope($event->getEmail())]);
        }
        $rules = $this->rulesCache[$cacheKey];

        $match = PatternMatcher::findMatching($rules, $host, 'getHost');
        if (!$match) {
            return;
        }

        if (!$event->isInitialScan()) {
            self::incrementCounter($this->em, $match);
        }
        $this->ms->setAsChecked($msg, $event->getEmail());
        $event->setWhitelist(true);
        $event->stopPropagation();
    }

    public function clearRuntimeCache(): void
    {
        $this->rulesCache = [];
    }
}
