<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Per-message scoring log: what contributed to the final score and what the
 * engine decided (ham / quarantine / spam).
 *
 * @ORM\Table(name="antispam_spam_score_log", indexes={
 *   @ORM\Index(name="idx_account_email", columns={"account_email"}),
 *   @ORM\Index(name="idx_scored_at", columns={"scored_at"})
 * })
 * @ORM\Entity(repositoryClass="AntispamBundle\Repository\SpamScoreLogRepository")
 */
class SpamScoreLog
{
    const DECISION_HAM = 'ham';
    const DECISION_QUARANTINE = 'quarantine';
    const DECISION_SPAM = 'spam';
    const DECISION_WHITELISTED = 'whitelisted';

    /**
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\Column(name="account_email", type="string", length=255, nullable=true)
     */
    private $accountEmail;

    /**
     * @ORM\Column(name="sender", type="string", length=255, nullable=true)
     */
    private $sender;

    /**
     * @ORM\Column(name="subject", type="string", length=512, nullable=true)
     */
    private $subject;

    /**
     * @ORM\Column(name="score", type="integer")
     */
    private $score = 0;

    /**
     * @ORM\Column(name="decision", type="string", length=16)
     */
    private $decision = self::DECISION_HAM;

    /**
     * JSON array of {rule: string, score: int} entries.
     *
     * @ORM\Column(name="reasons", type="text", nullable=true)
     */
    private $reasons;

    /**
     * @ORM\Column(name="scored_at", type="datetime")
     */
    private $scoredAt;

    public function __construct()
    {
        $this->scoredAt = new \DateTime();
    }

    public function getId() { return $this->id; }

    public function getAccountEmail() { return $this->accountEmail; }
    public function setAccountEmail($e) { $this->accountEmail = $e; return $this; }

    public function getSender() { return $this->sender; }
    public function setSender($s) { $this->sender = $s; return $this; }

    public function getSubject() { return $this->subject; }
    public function setSubject($s)
    {
        if ($s !== null && strlen($s) > 500) {
            $s = substr($s, 0, 500);
        }
        $this->subject = $s;
        return $this;
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
}
