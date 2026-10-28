<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\PluginReportRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * Spam / not-spam report sent from the Thunderbird plugin — logged in or not —
 * so the admin can see who reported what (the shared feed only keeps hashed
 * fingerprints).
 */
#[ORM\Entity(repositoryClass: PluginReportRepository::class)]
#[ORM\Table(name: 'antispam_plugin_report')]
#[ORM\Index(name: 'idx_reported_at', columns: ['reported_at'])]
class PluginReport
{
    /** How long reports are kept; older ones are purged on each new report. */
    const RETENTION_DAYS = 180;

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'verdict', type: 'string', length: 8)]
    private $verdict;

    /** Antispam account the plugin was logged in to; null = anonymous report. */
    #[ORM\Column(name: 'account_email', type: 'string', length: 255, nullable: true)]
    private $accountEmail;

    #[ORM\Column(name: 'sender', type: 'string', length: 255, nullable: true)]
    private $sender;

    #[ORM\Column(name: 'subject', type: 'string', length: 512, nullable: true)]
    private $subject;

    #[ORM\Column(name: 'client_ip', type: 'string', length: 45, nullable: true)]
    private $clientIp;

    /**
     * Mail client account the message was in when that is not the mailbox of
     * the token (Thunderbird plugin 1.3.0+, informational, sent by the client).
     */
    #[ORM\Column(name: 'reported_from', type: 'string', length: 255, nullable: true)]
    private $reportedFrom;

    /** Fingerprints recorded in the shared spam DB. */
    #[ORM\Column(name: 'signals', type: 'integer')]
    private $signals = 0;

    /** JSON array of rule changes, e.g. "email_blacklist_added:x@y.pl". */
    #[ORM\Column(name: 'rules', type: 'text', nullable: true)]
    private $rules;

    #[ORM\Column(name: 'reported_at', type: 'datetime')]
    private $reportedAt;

    public function __construct()
    {
        $this->reportedAt = new \DateTime();
    }

    public function getId() { return $this->id; }

    public function getVerdict() { return $this->verdict; }
    public function setVerdict($v) { $this->verdict = $v; return $this; }

    public function getAccountEmail() { return $this->accountEmail; }
    public function setAccountEmail($e) { $this->accountEmail = $e; return $this; }

    public function getSender() { return $this->sender; }
    public function setSender($s)
    {
        $this->sender = $s !== null ? mb_substr($s, 0, 255) : null;
        return $this;
    }

    public function getSubject() { return $this->subject; }
    public function setSubject($s)
    {
        $this->subject = $s !== null ? mb_substr($s, 0, 500) : null;
        return $this;
    }

    public function getClientIp() { return $this->clientIp; }
    public function setClientIp($ip) { $this->clientIp = $ip !== null ? substr($ip, 0, 45) : null; return $this; }

    public function getReportedFrom() { return $this->reportedFrom; }
    public function setReportedFrom($v)
    {
        $this->reportedFrom = ($v === null || $v === '') ? null : mb_substr((string)$v, 0, 255);
        return $this;
    }

    public function getSignals() { return $this->signals; }
    public function setSignals($n) { $this->signals = (int)$n; return $this; }

    public function getRulesDecoded()
    {
        return $this->rules ? (json_decode($this->rules, true) ?: []) : [];
    }
    public function setRules(array $rules)
    {
        $this->rules = $rules ? json_encode(array_values($rules)) : null;
        return $this;
    }

    public function getReportedAt() { return $this->reportedAt; }
}
