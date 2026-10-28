<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PatternMatcher;
use Doctrine\ORM\EntityManagerInterface;

class CheckEmailWhitelist
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
            $email = strtolower(
                $msg->getHeaders()->get('sender')[0]->mailbox
                . '@' . $msg->getHeaders()->get('sender')[0]->host
            );
        } catch (\Throwable $e) {
            return;
        }
        if (!$email || $email === '@') return;

        $cacheKey = (string)$event->getEmail();
        if (!isset($this->rulesCache[$cacheKey])) {
            $this->rulesCache[$cacheKey] = $this->em->getRepository(EmailWhitelist::class)
                ->findBy(['email' => \AntispamBundle\Services\RuleOwnership::scope($event->getEmail())]);
        }
        $rules = $this->rulesCache[$cacheKey];

        $match = PatternMatcher::findMatching($rules, $email, 'getWhitelistemail');
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
