<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ComplexRuleMessage;
use AntispamBundle\Services\ComplexRuleService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\ScoringService;

/**
 * Complex rules (docs/complex-rules.md) in the IMAP pipeline:
 *  - whitelist(): with the white lists (priority 99998) - a matching
 *    "whitelist" rule short-circuits like CheckWhitelist;
 *  - check(): after the blacklists (99995) - spam / quarantine / score rules.
 *
 * The header block is read once; the body is downloaded only when a rule of
 * the mailbox has a body or attachment condition.
 */
class CheckComplexRules
{
    /** @var \WeakMap<MessageEvent, ComplexRuleMessage> the two passes share one parsed message */
    private \WeakMap $messages;

    public function __construct(
        private ComplexRuleService $rules,
        private MessageService $ms,
        private ?ScoringService $scoring = null,
    ) {
        $this->messages = new \WeakMap();
    }

    public function whitelist(MessageEvent $event)
    {
        $rules = $this->rules->rulesFor($event->getEmail());
        if (!$rules || !($msg = $this->messageOf($event))) {
            return;
        }
        $hit = $this->rules->matchWhitelist($rules, $msg);
        if (!$hit) {
            return;
        }
        if (!$event->isInitialScan()) {
            $this->rules->countHit($hit);
        }
        $event->addReasons([['rule' => $hit->reasonRule(), 'score' => 0]]);
        $this->ms->setAsChecked($event->getMessage(), $event->getEmail());
        $event->setWhitelist(true);
        $event->stopPropagation();
    }

    public function check(MessageEvent $event)
    {
        $rules = $this->rules->rulesFor($event->getEmail());
        if (!$rules || !($msg = $this->messageOf($event))) {
            return;
        }
        $result = $this->rules->matchOthers($rules, $msg, $this->scoring === null || $this->scoring->isScoringEnabled());
        if (!$result['hits']) {
            return;
        }
        if (!$event->isInitialScan()) {
            foreach ($result['hits'] as $hit) {
                $this->rules->countHit($hit);
            }
        }
        $event->setSpamscore($event->getSpamscore() + $result['score']);
        $event->addReasons($result['reasons']);
        if ($result['spam']) {
            $event->setSpam(true);
        }
        if ($result['quarantine']) {
            $event->setForcedQuarantine(true);
        }
    }

    private function messageOf(MessageEvent $event): ?ComplexRuleMessage
    {
        if (isset($this->messages[$event])) {
            return $this->messages[$event];
        }
        $imap = $event->getMessage();
        try {
            $headers = (string)$imap->getRawHeaders();
        } catch (\Throwable $e) {
            return null;
        }
        $size = null;
        try {
            $size = (int)$imap->getSize() ?: null;
        } catch (\Throwable $e) {}
        return $this->messages[$event] = $this->rules->message($headers, static function () use ($imap) {
            return (string)$imap->getRawMessage();
        }, (string)$event->getEmail(), $size);
    }
}
