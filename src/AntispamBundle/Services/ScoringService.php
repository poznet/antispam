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

    const DEFAULT_CLAMAV_DSN = 'tcp://127.0.0.1:3310';
    const DEFAULT_CLAMAV_SCORE = 15;
    const DEFAULT_CLAMAV_MAX_SIZE = 26214400; // 25 MiB
    const DEFAULT_CLAMAV_TIMEOUT = 30;

    const DEFAULT_VT_SCORE = 15;
    const DEFAULT_VT_THRESHOLD = 3; // min. engines flagging malicious to act
    const DEFAULT_VT_TIMEOUT = 15;

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
     * ClamAV attachment scanning is opt-in: it stays disabled until an admin
     * enables it and points it at a reachable clamd daemon.
     */
    public function isClamavEnabled()
    {
        return (bool)$this->readBool('scoring.clamav_enabled', false);
    }

    public function getClamavDsn()
    {
        return $this->readString('scoring.clamav_dsn', self::DEFAULT_CLAMAV_DSN);
    }

    public function getClamavScore()
    {
        return $this->readInt('scoring.clamav_score', self::DEFAULT_CLAMAV_SCORE);
    }

    public function getClamavMaxSize()
    {
        return $this->readInt('scoring.clamav_max_size', self::DEFAULT_CLAMAV_MAX_SIZE);
    }

    public function getClamavTimeout()
    {
        return $this->readInt('scoring.clamav_timeout', self::DEFAULT_CLAMAV_TIMEOUT);
    }

    /**
     * VirusTotal attachment lookup is opt-in: it stays disabled until an admin
     * enables it and provides an API key.
     */
    public function isVirusTotalEnabled()
    {
        return (bool)$this->readBool('scoring.vt_enabled', false);
    }

    public function getVirusTotalApiKey()
    {
        return trim($this->readString('scoring.vt_api_key', ''));
    }

    public function getVirusTotalScore()
    {
        return $this->readInt('scoring.vt_score', self::DEFAULT_VT_SCORE);
    }

    /**
     * Minimum number of VirusTotal engines flagging a file as malicious before
     * it is treated as a hit (guards against single-engine false positives).
     */
    public function getVirusTotalThreshold()
    {
        return max(1, $this->readInt('scoring.vt_threshold', self::DEFAULT_VT_THRESHOLD));
    }

    public function getVirusTotalTimeout()
    {
        return $this->readInt('scoring.vt_timeout', self::DEFAULT_VT_TIMEOUT);
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

    private function readString($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        return ($v === null || $v === '') ? $default : (string)$v;
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
