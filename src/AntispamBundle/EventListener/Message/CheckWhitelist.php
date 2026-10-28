<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PatternMatcher;
use Doctrine\ORM\EntityManagerInterface;

class CheckWhitelist
{
    private $em;
    private $ms;
    /** @var array<string, array> rules cached per account email for the lifetime of this listener */
    private $rulesCache = [];

    public function __construct(EntityManagerInterface $em, MessageService $ms)
    {
        $this->em = $em;
        $this->ms = $ms;
    }

    public function check(MessageEvent $event)
    {
        $msg = $event->getMessage();

        try {
            $host = strtolower((string)$msg->getHeaders()->get('sender')[0]->host);
        } catch (\Throwable $e) {
            return;
        }
        if (!$host) return;

        $cacheKey = (string)$event->getEmail();
        if (!isset($this->rulesCache[$cacheKey])) {
            $this->rulesCache[$cacheKey] = $this->em->getRepository(Whitelist::class)
                ->findBy(['email' => $event->getEmail()]);
        }
        $rules = $this->rulesCache[$cacheKey];

        $match = PatternMatcher::findMatching($rules, $host, 'getHost');
        if (!$match) {
            return;
        }

        if (!$event->isInitialScan()) {
            $match->setCounter($match->getCounter() + 1);
            $this->em->flush();
        }
        $this->ms->setAsChecked($msg);
        $event->setWhitelist(true);
        $event->stopPropagation();
    }
}
