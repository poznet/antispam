<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\UrlAnalyzer;

/**
 * Link protection: scores suspicious links in the message body (text/href
 * mismatch, IP hosts, shorteners, punycode, URI block lists, Safe Browsing).
 */
class CheckUrls
{
    private $analyzer;
    private $scoring;

    public function __construct(UrlAnalyzer $analyzer, ScoringService $scoring)
    {
        $this->analyzer = $analyzer;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->scoring->isUrlCheckEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        $msg = $event->getMessage();
        $html = '';
        $text = '';
        try {
            $html = (string)$msg->getBodyHtml();
        } catch (\Throwable $e) {
            // unsupported encoding etc. - inspect whatever else is available
        }
        try {
            $text = (string)$msg->getBodyText();
        } catch (\Throwable $e) {
        }
        if ($html === '' && $text === '') {
            return;
        }

        $result = $this->analyzer->analyze($html, $text, $this->scoring->getUrlConfig());
        if ($result['score'] > 0) {
            $event->setSpamscore($event->getSpamscore() + $result['score']);
            $event->addReasons($result['reasons']);
        }
    }
}
