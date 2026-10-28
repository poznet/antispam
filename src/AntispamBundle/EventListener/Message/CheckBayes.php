<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\Bayes\BayesService;
use AntispamBundle\Services\Bayes\BayesTokenizer;
use AntispamBundle\Services\ScoringService;

/**
 * Local learned classifier (naive Bayes, docs/bayes.md): adds points for a
 * high spam probability, takes a few off for a very low one (never for a
 * blacklisted sender). No-op while disabled or not trained enough.
 */
class CheckBayes
{
    public function __construct(private BayesService $bayes, private ScoringService $scoring)
    {
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->bayes->isEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        $result = $this->bayes->scoreFields(BayesTokenizer::fieldsFromImap($event->getMessage()), $event->getEmail(), $event->isBlacklist());
        if ($result['reason'] !== null) {
            $event->setSpamscore($event->getSpamscore() + $result['score']);
            $event->addReasons([$result['reason']]);
        }
    }
}
