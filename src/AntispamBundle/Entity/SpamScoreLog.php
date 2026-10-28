<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\SpamScoreLogRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * Per-message scoring log: what contributed to the final score and what the
 * engine decided (ham / quarantine / spam).
 */
#[ORM\Entity(repositoryClass: SpamScoreLogRepository::class)]
#[ORM\Table(name: 'antispam_spam_score_log')]
#[ORM\Index(name: 'idx_account_email', columns: ['account_email'])]
#[ORM\Index(name: 'idx_scored_at', columns: ['scored_at'])]
#[ORM\Index(name: 'idx_decision_scored_at', columns: ['decision', 'scored_at'])]
#[ORM\Index(name: 'idx_account_scored_at', columns: ['account_email', 'scored_at'])]
#[ORM\Index(name: 'idx_account_sender', columns: ['account_email', 'sender'])]
class SpamScoreLog
{
    const DECISION_HAM = 'ham';
    const DECISION_QUARANTINE = 'quarantine';
    const DECISION_SPAM = 'spam';
    const DECISION_WHITELISTED = 'whitelisted';

    /** Who made the decision. */
    const SOURCE_SCAN = 'scan';       // server scan (cron / panel)
    const SOURCE_PLUGIN = 'plugin';   // mail client plugin check - never moves anything on the server
    const SOURCE_RETRO = 'retro';     // retroactive pass after a new blacklist rule

    /** What happened to the message on the server. */
    const OUTCOME_NONE = 'none';              // left where it was
    const OUTCOME_QUARANTINED = 'quarantined';
    const OUTCOME_SPAM_FOLDER = 'spam_folder';
    const OUTCOME_DELETED = 'deleted';
    const OUTCOME_MOVE_FAILED = 'move_failed'; // decision made, but the move failed - still in INBOX

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'account_email', type: 'string', length: 255, nullable: true)]
    private $accountEmail;

    #[ORM\Column(name: 'sender', type: 'string', length: 255, nullable: true)]
    private $sender;

    #[ORM\Column(name: 'subject', type: 'string', length: 512, nullable: true)]
    private $subject;

    #[ORM\Column(name: 'score', type: 'integer')]
    private $score = 0;

    #[ORM\Column(name: 'decision', type: 'string', length: 16)]
    private $decision = self::DECISION_HAM;

    /** JSON array of {rule: string, score: int} entries. */
    #[ORM\Column(name: 'reasons', type: 'text', nullable: true)]
    private $reasons;

    #[ORM\Column(name: 'scored_at', type: 'datetime')]
    private $scoredAt;

    /** SOURCE_* - null for entries written before it was recorded. */
    #[ORM\Column(name: 'source', type: 'string', length: 16, nullable: true)]
    private $source;

    /** OUTCOME_* - null for entries written before it was recorded. */
    #[ORM\Column(name: 'outcome', type: 'string', length: 16, nullable: true)]
    private $outcome;

    /** Logged during the first scan of a newly connected mailbox - left out of stats and the dashboard. */
    #[ORM\Column(name: 'initial_scan', type: 'boolean', options: ['default' => false])]
    private $initialScan = false;

    public function __construct()
    {
        $this->scoredAt = new \DateTime();
    }

    public function getId() { return $this->id; }

    public function getAccountEmail() { return $this->accountEmail; }
    public function setAccountEmail($e) { $this->accountEmail = self::clip($e, 255); return $this; }

    public function getSender() { return $this->sender; }
    public function setSender($s) { $this->sender = self::clip($s, 255); return $this; }

    public function getSubject() { return $this->subject; }
    public function setSubject($s)
    {
        $this->subject = self::clip($s, 500);
        return $this;
    }

    /**
     * Valid UTF-8 cut to $chars characters. A value longer than its column or
     * a byte cut through a multi-byte character makes MariaDB (strict mode)
     * reject the INSERT, which closes the EntityManager for the rest of the
     * scan. QuarantineService matches log rows on the same clipped subject.
     */
    public static function clip($value, $chars)
    {
        if ($value === null) {
            return null;
        }
        $value = mb_scrub((string)$value, 'UTF-8');
        return mb_strlen($value, 'UTF-8') > $chars ? mb_substr($value, 0, $chars, 'UTF-8') : $value;
    }

    public function getScore() { return $this->score; }
    public function setScore($score) { $this->score = (int)$score; return $this; }

    public function getDecision() { return $this->decision; }
    public function setDecision($d) { $this->decision = $d; return $this; }

    public function getReasons() { return $this->reasons; }
    public function getReasonsDecoded()
    {
        return $this->reasons ? json_decode($this->reasons, true) : [];
    }
    public function setReasons($reasons)
    {
        $this->reasons = is_array($reasons) ? json_encode($reasons) : $reasons;
        return $this;
    }

    public function getScoredAt() { return $this->scoredAt; }
    public function setScoredAt(\DateTime $dt) { $this->scoredAt = $dt; return $this; }

    public function getSource() { return $this->source; }
    public function setSource($source) { $this->source = $source; return $this; }

    public function getOutcome() { return $this->outcome; }
    public function setOutcome($outcome) { $this->outcome = $outcome; return $this; }

    public function isInitialScan() { return $this->initialScan; }
    public function setInitialScan($initialScan) { $this->initialScan = (bool)$initialScan; return $this; }
}
