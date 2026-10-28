<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PatternMatcher;
use Doctrine\ORM\EntityManagerInterface;

class CheckEmailWhitelist
{
    use SenderRuleTrait;

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

        $from = self::fromAddress($event);
        if ($from === null) {
            return;
        }
        $email = $from[0];

        $cacheKey = (string)$event->getEmail();
        if (!isset($this->rulesCache[$cacheKey])) {
            $this->rulesCache[$cacheKey] = $this->em->getRepository(EmailWhitelist::class)
                ->findBy(['email' => $event->getEmail()]);
        }
        $rules = $this->rulesCache[$cacheKey];

        $match = PatternMatcher::findMatching($rules, $email, 'getWhitelistemail');
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
}
