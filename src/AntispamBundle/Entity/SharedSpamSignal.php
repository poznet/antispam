<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * A privacy-preserving fingerprint of a spam message shared between antispam
 * instances ("centralized spam DB").
 *
 * Instead of storing raw e-mail content we keep one-way SHA-256 hashes of two
 * signals:
 *   - "sender": the normalized From address (spammers reuse addresses heavily)
 *   - "body":   the normalized, signature-stripped message body (catches a
 *               whole campaign even when each copy is personalized)
 *
 * Each instance can act both as a hub (serving its signals over the API) and a
 * client (pulling other instances' signals). `origin` distinguishes signals we
 * detected ourselves ("local", eligible to be pushed out) from signals pulled
 * from a remote hub ("remote"). `reports` accumulates how many times a signal
 * has been seen so a scoring listener can require corroboration before trusting
 * it.
 *
 * @ORM\Table(name="antispam_shared_spam_signal", uniqueConstraints={
 *   @ORM\UniqueConstraint(name="uniq_type_hash", columns={"type", "hash"})
 * }, indexes={
 *   @ORM\Index(name="idx_updated_at", columns={"updated_at"}),
 *   @ORM\Index(name="idx_origin", columns={"origin"})
 * })
 * @ORM\Entity(repositoryClass="AntispamBundle\Repository\SharedSpamSignalRepository")
 */
class SharedSpamSignal
{
    const TYPE_SENDER = 'sender';
    const TYPE_BODY = 'body';

    const ORIGIN_LOCAL = 'local';
    const ORIGIN_REMOTE = 'remote';

    /**
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\Column(name="type", type="string", length=16)
     */
    private $type;

    /**
     * Lower-case hex SHA-256 (64 chars).
     *
     * @ORM\Column(name="hash", type="string", length=64)
     */
    private $hash;

    /**
     * @ORM\Column(name="origin", type="string", length=16)
     */
    private $origin = self::ORIGIN_LOCAL;

    /**
     * How many observations this signal has accumulated (local + remote).
     *
     * @ORM\Column(name="reports", type="integer")
     */
    private $reports = 1;

    /**
     * @ORM\Column(name="created_at", type="datetime")
     */
    private $createdAt;

    /**
     * @ORM\Column(name="updated_at", type="datetime")
     */
    private $updatedAt;

    public function __construct()
    {
        $this->createdAt = new \DateTime();
        $this->updatedAt = new \DateTime();
    }

    public function getId() { return $this->id; }

    public function getType() { return $this->type; }
    public function setType($t) { $this->type = $t; return $this; }

    public function getHash() { return $this->hash; }
    public function setHash($h) { $this->hash = $h; return $this; }

    public function getOrigin() { return $this->origin; }
    public function setOrigin($o) { $this->origin = $o; return $this; }

    public function getReports() { return $this->reports; }
    public function setReports($r) { $this->reports = (int)$r; return $this; }
    public function addReport($n = 1) { $this->reports += (int)$n; return $this; }

    public function getCreatedAt() { return $this->createdAt; }
    public function setCreatedAt(\DateTime $dt) { $this->createdAt = $dt; return $this; }

    public function getUpdatedAt() { return $this->updatedAt; }
    public function setUpdatedAt(\DateTime $dt) { $this->updatedAt = $dt; return $this; }
    public function touch() { $this->updatedAt = new \DateTime(); return $this; }
}
