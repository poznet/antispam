<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use AntispamBundle\Services\ScoringService;

/**
 * Attachment policy: blocked file types, double extensions, disguised
 * executables, executables inside archives, Office macros, encrypted
 * archives. Runs before ClamAV / VirusTotal and needs neither.
 */
class CheckAttachmentPolicy
{
    use AttachmentExtractorTrait;

    private $analyzer;
    private $scoring;

    public function __construct(AttachmentPolicyAnalyzer $analyzer, ScoringService $scoring)
    {
        $this->analyzer = $analyzer;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->scoring->isAttachmentPolicyEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore() || $event->isDecidedInRescan()) {
            return;
        }

        $attachments = [];
        foreach ($this->extractAttachments($event) as $attachment) {
            $data = $this->decodeAttachment($attachment);
            $attachments[] = [
                'filename' => $this->filenameOf($attachment),
                'data' => $data === null ? '' : $data,
            ];
        }
        if (!$attachments) {
            return;
        }

        $result = $this->analyzer->analyze($attachments, $this->scoring->getAttachmentPolicyConfig());
        if ($result['score'] > 0) {
            $event->setSpamscore($event->getSpamscore() + $result['score']);
            $event->addReasons($result['reasons']);
        }
    }
}
