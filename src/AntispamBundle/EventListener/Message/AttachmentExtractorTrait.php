<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;

/**
 * Shared helpers for listeners that need to read message attachments from a
 * Ddeboer\Imap message. All accessors are defensive: any error yields an empty
 * result rather than breaking the scoring pipeline.
 */
trait AttachmentExtractorTrait
{
    /**
     * @return array list of Ddeboer\Imap attachment parts (empty on any error)
     */
    protected function extractAttachments(MessageEvent $event)
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

    /**
     * @return string|null decoded bytes, or null when unavailable
     */
    protected function decodeAttachment($attachment)
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

    protected function filenameOf($attachment)
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
