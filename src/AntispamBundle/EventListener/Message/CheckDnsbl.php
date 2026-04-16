<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\DnsblService;
use AntispamBundle\Services\ScoringService;

/**
 * Extracts the connecting IP from the latest Received header and checks it
 * against the configured DNSBL providers. Each hit adds the provider's
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
            CheckHeaders::addReasons($event, $reasons);
        }
    }

    private function extractIp(MessageEvent $event)
    {
        try {
            $msg = $event->getMessage();
            $received = $msg->getHeaders()->get('received');
            if (is_array($received)) {
                $received = implode("\n", $received);
            }
            if (!$received) {
                return null;
            }
            if (preg_match('/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/', (string)$received, $m)) {
                return $m[1];
            }
            if (preg_match('/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/', (string)$received, $m)) {
                return $m[1];
            }
        } catch (\Throwable $e) {
            return null;
        }
        return null;
    }
}
