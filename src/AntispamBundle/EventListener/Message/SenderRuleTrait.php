<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Shared by the white/blacklist listeners: which address the rules are
 * matched against, and race-free hit counters.
 */
trait SenderRuleTrait
{
    /**
     * Lower-cased From address and its domain - the same address every other
     * check (score log, impersonation, retroactive pass, plugin scanner)
     * uses. The Sender: header is not used: the sending system sets it and a
     * spammer could put a whitelisted domain there.
     *
     * @return array{0:string, 1:string}|null [address, host]; null when unreadable
     */
    private static function fromAddress(MessageEvent $event)
    {
        try {
            $from = $event->getMessage()->getFrom();
        } catch (\Throwable $e) {
            return null;
        }
        if (!$from) {
            return null;
        }
        $host = strtolower(trim((string)$from->getHostname()));
        $mailbox = strtolower(trim((string)$from->getMailbox()));
        if ($host === '' || $mailbox === '') {
            return null;
        }
        return [$mailbox . '@' . $host, $host];
    }

    /** counter = counter + 1 in SQL: two scans at once must not lose hits. */
    private static function incrementCounter(EntityManagerInterface $em, $rule)
    {
        if ($rule->getId() === null) {
            return;
        }
        $class = $em->getClassMetadata(get_class($rule))->getName();
        $em->createQuery('UPDATE ' . $class . ' r SET r.counter = r.counter + 1 WHERE r.id = :id')
            ->setParameter('id', $rule->getId())
            ->execute();
    }
}
