<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\HeaderAnalyzer;
use AntispamBundle\Services\ScoringService;

/**
 * Runs header-based heuristics (SPF/DKIM/DMARC, mismatched reply-to, suspicious
 * subject, missing Message-ID, etc.) and adds their points to the event score.
 *
 * Reasons are collected on the event so the final decision listener can log
 * them.
 */
class CheckHeaders
{
    private $analyzer;
    private $scoring;

    public function __construct(HeaderAnalyzer $analyzer, ScoringService $scoring)
    {
        $this->analyzer = $analyzer;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->scoring->isHeaderCheckEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        try {
            $analysis = $this->analyzer->analyzeImap($event->getMessage());
        } catch (\Throwable $e) {
            return;
        }

        if ($analysis['score'] > 0) {
            $event->setSpamscore($event->getSpamscore() + $analysis['score']);
            $event->addReasons($analysis['reasons']);
        }
    }
}
