<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SpamSignalService;

/**
 * Scores incoming mail against the shared spam feed: if the message's sender or
 * (signature-stripped) body fingerprint matches a signal seen by enough
 * instances, its score is added so spam confirmed elsewhere is caught here too.
 */
class CheckSharedFeed
{
    private $feed;
    private $scoring;

    public function __construct(SpamSignalService $feed, ScoringService $scoring)
    {
        $this->feed = $feed;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->feed->isEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        try {
            $hits = $this->feed->matchMessage($event->getMessage());
        } catch (\Throwable $e) {
            return;
        }
        if (!$hits) {
            return;
        }

        $score = $this->feed->getMatchScore();
        $reasons = [];
        foreach ($hits as $hit) {
            $event->setSpamscore($event->getSpamscore() + $score);
            $reasons[] = [
                'rule' => 'shared_feed:' . $hit['type'] . ' (reports=' . $hit['reports'] . ')',
                'score' => $score,
            ];
        }
        CheckHeaders::addReasons($event, $reasons);
    }
}
