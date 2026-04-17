<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\HeaderAnalyzer;
use AntispamBundle\Services\ScoringService;

/**
 * Runs header-based heuristics (SPF/DKIM/DMARC, mismatched reply-to, suspicious
 * subject, missing Message-ID, etc.) and adds their points to the event score.
 *
 * Reasons are stashed on the event via the message-level reasons list so the
 * final decision listener can log them.
 */
class CheckHeaders
{
    public static $REASONS_KEY = '_antispam_reasons';

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
            self::addReasons($event, $analysis['reasons']);
        }
    }

    public static function addReasons(MessageEvent $event, array $reasons)
    {
        $existing = self::getReasons($event);
        $event->{self::$REASONS_KEY} = array_merge($existing, $reasons);
    }

    public static function getReasons(MessageEvent $event)
    {
        return isset($event->{self::$REASONS_KEY}) && is_array($event->{self::$REASONS_KEY})
            ? $event->{self::$REASONS_KEY}
            : [];
    }
}
