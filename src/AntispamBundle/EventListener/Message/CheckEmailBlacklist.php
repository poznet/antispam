<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PatternMatcher;
use AntispamBundle\Services\ScoringService;
use Ddeboer\Imap\Exception\Exception;
use Doctrine\ORM\EntityManagerInterface;

class CheckEmailBlacklist
{
    private $em;
    private $ms;
    private $scoring;

    public function __construct(EntityManagerInterface $em, MessageService $ms, ScoringService $scoring = null)
    {
        $this->em = $em;
        $this->ms = $ms;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        $msg = $event->getMessage();

        try {
            $email = strtolower(
                $msg->getHeaders()->get('sender')[0]->mailbox
                . '@' . $msg->getHeaders()->get('sender')[0]->host
            );
        } catch (Exception $e) {
            return;
        } catch (\Throwable $e) {
            return;
        }
        if (!$email || $email === '@') return;

        $rules = $this->em->getRepository('AntispamBundle:EmailBlacklist')
            ->findBy(['email' => $event->getEmail()]);

        $match = PatternMatcher::findMatching($rules, $email, 'getBlacklistemail');
        if (!$match) {
            return;
        }

        $match->setCounter($match->getCounter() + 1);
        $this->em->flush();

        if ($this->scoring && $this->scoring->isScoringEnabled()) {
            $event->setSpamscore($event->getSpamscore() + $match->getScore());
            CheckHeaders::addReasons($event, [[
                'rule' => 'email_blacklist:' . $match->getBlacklistemail() . ' (' . $match->getPatternType() . ')',
                'score' => $match->getScore(),
            ]]);
            $event->setBlacklist(true);
            return;
        }

        $this->ms->setAsChecked($msg);
        $event->setBlacklist(true);
        $event->setSpam(true);
    }
}
