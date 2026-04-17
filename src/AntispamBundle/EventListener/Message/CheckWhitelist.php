<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PatternMatcher;
use Ddeboer\Imap\Exception\Exception;
use Doctrine\ORM\EntityManagerInterface;

class CheckWhitelist
{
    private $em;
    private $ms;

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
        } catch (Exception $e) {
            return;
        } catch (\Throwable $e) {
            return;
        }
        if (!$host) return;

        $rules = $this->em->getRepository('AntispamBundle:Whitelist')
            ->findBy(['email' => $event->getEmail()]);

        $match = PatternMatcher::findMatching($rules, $host, 'getHost');
        if (!$match) {
            return;
        }

        $match->setCounter($match->getCounter() + 1);
        $this->em->flush();
        $this->ms->setAsChecked($msg);
        $event->setWhitelist(true);
        $event->stopPropagation();
    }
}
