<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\DnsblService;
use AntispamBundle\Services\RawMessageParser;
use AntispamBundle\Services\ScoringService;

/**
 * Extracts the connecting IP from the topmost Received header with a public
 * address and checks it against the configured DNSBL providers. Each hit adds the provider's
 * configured score to the event.
 */
class CheckDnsbl
{
    private $dnsbl;
    private $scoring;

    public function __construct(DnsblService $dnsbl, ScoringService $scoring)
    {
        $this->dnsbl = $dnsbl;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->scoring->isDnsblEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        $ip = $this->extractIp($event);
        if (!$ip) {
            return;
        }

        $reasons = [];
        $score = $this->dnsbl->scoreForIp($ip, $reasons);
        if ($score > 0) {
            $event->setSpamscore($event->getSpamscore() + $score);
            $event->addReasons($reasons);
        }
    }

    /**
     * Connecting IP from the raw Received headers. imap_headerinfo() (what
     * getHeaders() returns) has no Received lines at all, so the raw header
     * block is needed; the extractor is shared with the plugin scanner.
     */
    private function extractIp(MessageEvent $event)
    {
        try {
            $raw = $event->getMessage()->getRawHeaders();
        } catch (\Throwable $e) {
            return null;
        }
        return RawMessageParser::connectingIpFromReceived(RawMessageParser::headerValues($raw, 'received'));
    }
}
