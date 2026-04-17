<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Event\MessageEvent;
use Doctrine\ORM\EntityManagerInterface;
use Poznet\ConfigBundle\Service\ConfigService;

/**
 * Centralizes spam scoring configuration and the ham/quarantine/spam decision.
 *
 * Thresholds are stored in ConfigBundle (antispam.scoring.*) with sane
 * defaults. The service also writes a SpamScoreLog entry per processed message
 * so admins can audit "why was this flagged".
 */
class ScoringService
{
    const DEFAULT_SPAM_THRESHOLD = 10;
    const DEFAULT_QUARANTINE_THRESHOLD = 5;

    private $em;
    private $config;

    public function __construct(EntityManagerInterface $em, ConfigService $config = null)
    {
        $this->em = $em;
        $this->config = $config;
    }

    public function getSpamThreshold()
    {
        return $this->readInt('scoring.spam_threshold', self::DEFAULT_SPAM_THRESHOLD);
    }

    public function getQuarantineThreshold()
    {
        return $this->readInt('scoring.quarantine_threshold', self::DEFAULT_QUARANTINE_THRESHOLD);
    }

    public function isScoringEnabled()
    {
        return (bool)$this->readBool('scoring.enabled', true);
    }

    public function isDnsblEnabled()
    {
        return (bool)$this->readBool('scoring.dnsbl_enabled', true);
    }

    public function isHeaderCheckEnabled()
    {
        return (bool)$this->readBool('scoring.header_check_enabled', true);
    }

    public function isLoggingEnabled()
    {
        return (bool)$this->readBool('scoring.log_enabled', true);
    }

    /**
     * Apply the final spam/quarantine/ham decision to the event based on the
     * accumulated score and persist a SpamScoreLog entry.
     */
    public function decide(MessageEvent $event, array $reasons, $sender = null, $subject = null)
    {
        $score = $event->getSpamscore();
        $decision = SpamScoreLog::DECISION_HAM;

        if ($event->isWhitelist()) {
            $decision = SpamScoreLog::DECISION_WHITELISTED;
        } elseif ($event->isSpam() || $score >= $this->getSpamThreshold()) {
            $decision = SpamScoreLog::DECISION_SPAM;
            $event->setSpam(true);
        } elseif ($score >= $this->getQuarantineThreshold()) {
            $decision = SpamScoreLog::DECISION_QUARANTINE;
        }

        if ($this->isLoggingEnabled()) {
            $log = new SpamScoreLog();
            $log->setAccountEmail($event->getEmail())
                ->setSender($sender)
                ->setSubject($subject)
                ->setScore($score)
                ->setDecision($decision)
                ->setReasons($reasons);
            $this->em->persist($log);
            $this->em->flush();
        }

        return $decision;
    }

    private function readInt($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        return ($v === null || $v === '') ? $default : (int)$v;
    }

    private function readBool($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        if ($v === null || $v === '') return $default;
        if (is_bool($v)) return $v;
        return in_array(strtolower((string)$v), ['1', 'true', 'yes', 'on'], true);
    }
}
