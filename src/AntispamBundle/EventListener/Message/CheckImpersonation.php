<?php

namespace AntispamBundle\EventListener\Message;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ImpersonationAnalyzer;
use AntispamBundle\Services\ScoringService;

/**
 * Impersonation / BEC protection: VIP display-name spoofing, lookalike
 * domains of protected domains and spoofing of the account's own domain.
 */
class CheckImpersonation
{
    private $analyzer;
    private $scoring;
    private $vips;

    public function __construct(ImpersonationAnalyzer $analyzer, ScoringService $scoring)
    {
        $this->analyzer = $analyzer;
        $this->scoring = $scoring;
    }

    public function check(MessageEvent $event)
    {
        if (!$this->scoring->isScoringEnabled() || !$this->scoring->isImpersonationEnabled()) {
            return;
        }
        if ($event->isWhitelist() || $event->isCheckedbefore()) {
            return;
        }

        $msg = $event->getMessage();
        $data = ['from_name' => '', 'from_email' => '', 'auth_results' => ''];
        try {
            $from = $msg->getFrom();
            if ($from) {
                $data['from_email'] = (string)$from->getAddress();
                $data['from_name'] = (string)$from->getName();
            }
        } catch (\Throwable $e) {
            return;
        }
        try {
            $auth = $msg->getHeaders()->get('authentication-results');
            $data['auth_results'] = is_array($auth) ? implode("\n", $auth) : (string)$auth;
        } catch (\Throwable $e) {
            // no Authentication-Results header: internal-spoof check is skipped
        }

        if ($this->vips === null) {
            $this->vips = ImpersonationAnalyzer::parseVips($this->scoring->getVipList());
        }

        $result = $this->analyzer->analyze(
            $data,
            $this->scoring->getProtectedDomains($event->getEmail()),
            $this->vips,
            $this->scoring->getImpersonationScores()
        );
        if ($result['score'] > 0) {
            $event->setSpamscore($event->getSpamscore() + $result['score']);
            $event->addReasons($result['reasons']);
        }
    }
}
