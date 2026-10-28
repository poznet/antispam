<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\PhishingReportRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * Message a mailbox owner reported as a phishing attempt from a mail client
 * plugin. Unlike spam reports the full source (headers, body, attachments) is
 * kept, so the admin can inspect it in the panel, build filters from it and
 * forward it (e.g. to CERT Polska) as an .eml file.
 *
 * The list view never loads `raw` (see PhishingReportRepository::findList).
 */
#[ORM\Entity(repositoryClass: PhishingReportRepository::class)]
#[ORM\Table(name: 'antispam_phishing_report')]
#[ORM\Index(name: 'idx_phishing_created_at', columns: ['created_at'])]
#[ORM\Index(name: 'idx_phishing_account_sha', columns: ['account_email', 'sha256'])]
class PhishingReport
{
    /** Reports older than this are purged when a new one arrives. */
    const RETENTION_DAYS = 365;

    const STATUS_NEW = 'new';
    const STATUS_CONFIRMED = 'confirmed';
    const STATUS_FALSE_POSITIVE = 'false_positive';
    const STATUS_REPORTED = 'reported';

    const STATUSES = [
        self::STATUS_NEW => 'nowe',
        self::STATUS_CONFIRMED => 'potwierdzony phishing',
        self::STATUS_REPORTED => 'zgłoszone do CERT',
        self::STATUS_FALSE_POSITIVE => 'to nie phishing',
    ];

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'created_at', type: 'datetime')]
    private $createdAt;

    /** Last time the same message was reported again by the same account. */
    #[ORM\Column(name: 'last_reported_at', type: 'datetime')]
    private $lastReportedAt;

    #[ORM\Column(name: 'report_count', type: 'integer')]
    private $reportCount = 1;

    #[ORM\Column(name: 'account_email', type: 'string', length: 255)]
    private $accountEmail;

    /** thunderbird | outlook | other */
    #[ORM\Column(name: 'client', type: 'string', length: 16, nullable: true)]
    private $client;

    #[ORM\Column(name: 'client_ip', type: 'string', length: 45, nullable: true)]
    private $clientIp;

    #[ORM\Column(name: 'sender', type: 'string', length: 255, nullable: true)]
    private $sender;

    #[ORM\Column(name: 'sender_name', type: 'string', length: 255, nullable: true)]
    private $senderName;

    #[ORM\Column(name: 'reply_to', type: 'string', length: 255, nullable: true)]
    private $replyTo;

    #[ORM\Column(name: 'return_path', type: 'string', length: 255, nullable: true)]
    private $returnPath;

    #[ORM\Column(name: 'subject', type: 'string', length: 512, nullable: true)]
    private $subject;

    #[ORM\Column(name: 'message_id', type: 'string', length: 255, nullable: true)]
    private $messageId;

    /** Public IP of the host that handed the message to the recipient's server. */
    #[ORM\Column(name: 'connecting_ip', type: 'string', length: 45, nullable: true)]
    private $connectingIp;

    #[ORM\Column(name: 'size', type: 'integer')]
    private $size = 0;

    /** The client cut the source at its upload limit (attachments may be missing). */
    #[ORM\Column(name: 'truncated', type: 'boolean')]
    private $truncated = false;

    #[ORM\Column(name: 'sha256', type: 'string', length: 64)]
    private $sha256;

    #[ORM\Column(name: 'status', type: 'string', length: 16)]
    private $status = self::STATUS_NEW;

    #[ORM\Column(name: 'note', type: 'text', nullable: true)]
    private $note;

    /** Full RFC 822 source as received from the plugin. */
    #[ORM\Column(name: 'raw', type: 'blob')]
    private $raw;

    public function __construct()
    {
        $this->createdAt = new \DateTime();
        $this->lastReportedAt = new \DateTime();
    }

    public function getId() { return $this->id; }
    public function getCreatedAt() { return $this->createdAt; }

    public function getLastReportedAt() { return $this->lastReportedAt; }
    public function getReportCount() { return $this->reportCount; }

    /** Same message reported again: count it instead of storing a copy. */
    public function reportedAgain()
    {
        $this->reportCount++;
        $this->lastReportedAt = new \DateTime();
        return $this;
    }

    public function getAccountEmail() { return $this->accountEmail; }
    public function setAccountEmail($v) { $this->accountEmail = $v; return $this; }

    public function getClient() { return $this->client; }
    public function setClient($v) { $this->client = $v; return $this; }

    public function getClientIp() { return $this->clientIp; }
    public function setClientIp($v) { $this->clientIp = $v; return $this; }

    public function getSender() { return $this->sender; }
    public function setSender($v) { $this->sender = self::clip($v, 255); return $this; }

    public function getSenderName() { return $this->senderName; }
    public function setSenderName($v) { $this->senderName = self::clip($v, 255); return $this; }

    public function getReplyTo() { return $this->replyTo; }
    public function setReplyTo($v) { $this->replyTo = self::clip($v, 255); return $this; }

    public function getReturnPath() { return $this->returnPath; }
    public function setReturnPath($v) { $this->returnPath = self::clip($v, 255); return $this; }

    public function getSubject() { return $this->subject; }
    public function setSubject($v) { $this->subject = self::clip($v, 512); return $this; }

    public function getMessageId() { return $this->messageId; }
    public function setMessageId($v) { $this->messageId = self::clip($v, 255); return $this; }

    public function getConnectingIp() { return $this->connectingIp; }
    public function setConnectingIp($v) { $this->connectingIp = $v; return $this; }

    public function getSize() { return $this->size; }
    public function isTruncated() { return $this->truncated; }
    public function setTruncated($v) { $this->truncated = (bool)$v; return $this; }

    public function getSha256() { return $this->sha256; }

    public function getStatus() { return $this->status; }
    public function setStatus($v)
    {
        if (!array_key_exists($v, self::STATUSES)) {
            throw new \InvalidArgumentException('Unknown status: ' . $v);
        }
        $this->status = $v;
        return $this;
    }

    /** Hostile mail may carry invalid UTF-8 - store it scrubbed and cut to the column size. */
    private static function clip($v, $length)
    {
        return $v === null ? null : mb_substr(mb_scrub((string)$v, 'UTF-8'), 0, $length, 'UTF-8');
    }

    public function getNote() { return $this->note; }
    public function setNote($v) { $this->note = ($v === null || trim($v) === '') ? null : $v; return $this; }

    /** Raw source as a string (Doctrine hands blobs back as streams). */
    public function getRaw()
    {
        if (is_resource($this->raw)) {
            rewind($this->raw);
            $this->raw = stream_get_contents($this->raw);
        }
        return (string)$this->raw;
    }

    public function setRaw($raw)
    {
        $this->raw = (string)$raw;
        $this->size = strlen($this->raw);
        $this->sha256 = hash('sha256', $this->raw);
        return $this;
    }
}
