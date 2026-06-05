<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ClamavService;
use AntispamBundle\Services\ScoringService;

/**
 * Streams each message attachment through the ClamAV daemon. A malware hit
 * marks the message as spam outright and adds the configured score, so an
 * infected attachment is caught regardless of the other heuristics.
 *
 * Scanning is opt-in (disabled by default) because it requires a reachable
 * clamd instance. When the daemon is unreachable the scan is skipped silently
 * — a transport failure never penalises a legitimate message.
 */
class CheckAttachments
{
    private $clamav;
    private $scoring;

    public function __construct(ClamavService $clamav, ScoringService $scoring)
    {
        $this->clamav = $clamav;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->scoring->isClamavEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        $attachments = $this->extractAttachments($event);
        if (!$attachments) {
            return;
        }

        $dsn = $this->scoring->getClamavDsn();
        $timeout = $this->scoring->getClamavTimeout();
        $maxSize = $this->scoring->getClamavMaxSize();
        $score = $this->scoring->getClamavScore();

        foreach ($attachments as $attachment) {
            $data = $this->decodeAttachment($attachment);
            if ($data === null || $data === '') {
                continue;
            }
            // Respect clamd's StreamMaxLength; oversized parts are skipped
            // rather than truncated (a partial scan would be misleading).
            if ($maxSize > 0 && strlen($data) > $maxSize) {
                continue;
            }

            $result = $this->clamav->scan($data, $dsn, $timeout);
            if (!$result['clean']) {
                $event->setSpamscore($event->getSpamscore() + $score);
                $event->setSpam(true);
                CheckHeaders::addReasons($event, [[
                    'rule' => 'clamav:' . ($result['signature'] ?: 'unknown'),
                    'score' => $score,
                    'filename' => $this->filenameOf($attachment),
                ]]);
                // One infected attachment is enough to condemn the message.
                return;
            }
        }
    }

    /**
     * @return array list of Ddeboer\Imap attachment parts (empty on any error)
     */
    private function extractAttachments(MessageEvent $event)
    {
        try {
            $msg = $event->getMessage();
            if (!method_exists($msg, 'getAttachments')) {
                return [];
            }
            $attachments = $msg->getAttachments();
            return is_array($attachments) ? $attachments : [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    private function decodeAttachment($attachment)
    {
        try {
            if (method_exists($attachment, 'getDecodedContent')) {
                return $attachment->getDecodedContent();
            }
            if (method_exists($attachment, 'getContent')) {
                return $attachment->getContent();
            }
        } catch (\Throwable $e) {
            return null;
        }
        return null;
    }

    private function filenameOf($attachment)
    {
        try {
            if (method_exists($attachment, 'getFilename')) {
                return (string)$attachment->getFilename();
            }
        } catch (\Throwable $e) {
            // ignore
        }
        return '';
    }
}
