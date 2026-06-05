<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Entity\SharedSpamSignal;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\SpamSignalService;

/**
 * Records a fingerprint of every message this instance decides is spam into the
 * shared-feed table (origin = local). These are the signals later pushed to a
 * remote hub by `antispam:feed:sync`, so other instances benefit from what we
 * caught.
 *
 * Runs after the scoring decision but before the message is physically moved or
 * deleted, so the body is still available.
 */
class RecordSpamSignals
{
    private $feed;

    public function __construct(SpamSignalService $feed)
    {
        $this->feed = $feed;
    }

    public function record(MessageEvent $event)
    {
        if (!$this->feed->isEnabled() || !$event->isSpam() || $event->isCheckedbefore()) {
            return;
        }

        try {
            $signals = $this->feed->signalsForMessage($event->getMessage());
            if (!$signals) {
                return;
            }
            $this->feed->record($signals, SharedSpamSignal::ORIGIN_LOCAL);
            // The service leaves flushing to the caller; persist here so the
            // signal survives even if later listeners stop propagation.
            $this->feed->flush();
        } catch (\Throwable $e) {
            // Never let feed bookkeeping break the spam pipeline.
        }
    }
}
