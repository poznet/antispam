<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\VirusTotalService;

/**
 * Looks up each attachment's SHA-256 on VirusTotal. When the number of engines
 * flagging the file as malicious reaches the configured threshold, the message
 * is marked as spam and the configured score is added.
 *
 * Only the hash is sent to VirusTotal, never the attachment bytes. The check is
 * opt-in (needs an API key) and tolerant of failures: an unknown hash, a rate
 * limit, or a network error never penalises a legitimate message.
 */
class CheckAttachmentsVirusTotal
{
    use AttachmentExtractorTrait;

    private $virustotal;
    private $scoring;

    public function __construct(VirusTotalService $virustotal, ScoringService $scoring)
    {
        $this->virustotal = $virustotal;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->scoring->isVirusTotalEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        $attachments = $this->extractAttachments($event);
        if (!$attachments) {
            return;
        }

        $apiKey = $this->scoring->getVirusTotalApiKey();
        if ($apiKey === '') {
            return;
        }
        $timeout = $this->scoring->getVirusTotalTimeout();
        $threshold = $this->scoring->getVirusTotalThreshold();
        $score = $this->scoring->getVirusTotalScore();

        foreach ($attachments as $attachment) {
            $data = $this->decodeAttachment($attachment);
            if ($data === null || $data === '') {
                continue;
            }

            $hash = hash('sha256', $data);
            $result = $this->virustotal->lookupHash($hash, $apiKey, $timeout);
            if ($result['error'] !== null || !$result['found']) {
                continue;
            }

            if ($result['malicious'] >= $threshold) {
                $event->setSpamscore($event->getSpamscore() + $score);
                $event->setSpam(true);
                CheckHeaders::addReasons($event, [[
                    'rule' => 'virustotal:' . $result['malicious'] . '/' . $result['total'],
                    'score' => $score,
                    'filename' => $this->filenameOf($attachment),
                ]]);
                // One flagged attachment is enough to condemn the message.
                return;
            }
        }
    }
}
