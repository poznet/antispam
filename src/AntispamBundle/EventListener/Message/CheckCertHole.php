<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\DomainHelper;
use AntispamBundle\Services\ScoringService;

/**
 * CERT Polska "Lista Ostrzeżeń": scores mail whose sender domain (From,
 * Reply-To, Return-Path) or any body link points at a listed phishing domain
 * or one of its subdomains.
 */
class CheckCertHole

{
    private $cert;
    private $scoring;

    public function __construct(CertHoleService $cert, ScoringService $scoring)
    {
        $this->cert = $cert;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->cert->isEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        $msg = $event->getMessage();
        $senders = [];
        try {
            if ($from = $msg->getFrom()) {
                $senders[] = DomainHelper::normalize($from->getHostname());
            }
            foreach ($msg->getReplyTo() as $addr) {
                $senders[] = DomainHelper::normalize($addr->getHostname());
            }
            foreach ((array)$msg->getHeaders()->get('return_path') as $addr) {
                if (is_object($addr) && !empty($addr->host)) {
                    $senders[] = DomainHelper::normalize($addr->host);
                }
            }
        } catch (\Throwable $e) {
            // unparsable headers: use whatever was collected
        }

        $html = '';
        $text = '';
        try {
            $html = (string)$msg->getBodyHtml();
        } catch (\Throwable $e) {
        }
        try {
            $text = (string)$msg->getBodyText();
        } catch (\Throwable $e) {
        }

        $result = $this->cert->analyze(
            array_values(array_filter($senders)),
            CertHoleService::linkHosts($html, $text),
            $this->scoring->getSpamThreshold()
        );
        if ($result['score'] > 0) {
            $event->setSpamscore($event->getSpamscore() + $result['score']);
            $event->addReasons($result['reasons']);
        }
    }
}
