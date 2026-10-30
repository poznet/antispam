<?php

namespace AntispamBundle\Event;

use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\MessageInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * One IMAP message travelling through the `antispam.check.message` listener
 * pipeline; listeners record their verdicts and scores on it.
 */
class MessageEvent extends Event
{
    private $message;
    private $email;
    private $delete = false;
    private $whitelist = false;
    private $blacklist = false;
    private $spamscore = 0;
    private $spam = false;
    private $checkedbefore = false;
    /** @var array<int, array> scoring reasons collected by the pipeline listeners */
    private $reasons = [];
    /** IMAP connection the message came from; null = the legacy mailbox from the "E-mail" settings */
    private $connection;
    /** Delete spam instead of moving it to SPAM; null = global "delete" setting */
    private $deleteSpam;
    /** SpamScoreLog entry for this message, so later listeners can record where it went. */
    private $scoreLog;
    /** First scan of a newly connected mailbox: decide and move as usual, but keep it out of stats and rule hit counters. */
    private $initialScan = false;
    /**
     * Full re-check of the INBOX ("Przeskanuj całą skrzynkę ponownie", weekly
     * rescan): the "already checked" markers are ignored, spam is moved (never
     * deleted) and, like the initial scan, nothing counts in the statistics.
     */
    private $rescan = false;

    public function __construct(MessageInterface $message, $email = null, ?ConnectionInterface $connection = null, ?bool $deleteSpam = null)
    {
        $this->message = $message;
        $this->email = $email;
        $this->connection = $connection;
        $this->deleteSpam = $deleteSpam;
    }

    public function isInitialScan(): bool
    {
        return $this->initialScan;
    }

    public function setInitialScan(bool $initialScan)
    {
        $this->initialScan = $initialScan;
    }

    /**
     * Rescan of a message already on a blacklist: the verdict is final (a
     * blacklist hit is spam), so the costly content checks (headers, links,
     * attachments, DNS, Bayes) are skipped - they only add reasons.
     */
    public function isDecidedInRescan(): bool
    {
        return $this->rescan && $this->blacklist;
    }

    public function isRescan(): bool
    {
        return $this->rescan;
    }

    /** A rescan is also kept out of the statistics and rule hit counters (isInitialScan() = true). */
    public function setRescan(bool $rescan)
    {
        $this->rescan = $rescan;
        if ($rescan) {
            $this->initialScan = true;
        }
    }

    public function getConnection(): ?ConnectionInterface
    {
        return $this->connection;
    }

    public function getDeleteSpam(): ?bool
    {
        return $this->deleteSpam;
    }

    /** @return MessageInterface */
    public function getMessage()
    {
        return $this->message;
    }

    public function setMessage(MessageInterface $message)
    {
        $this->message = $message;
    }

    /** Address of the account being scanned (rules are scoped per account). */
    public function getEmail()
    {
        return $this->email;
    }

    public function setEmail($email)
    {
        $this->email = $email;
    }

    public function isDelete()
    {
        return $this->delete;
    }

    public function setDelete($delete)
    {
        $this->delete = $delete;
    }

    public function isWhitelist()
    {
        return $this->whitelist;
    }

    public function setWhitelist($whitelist)
    {
        $this->whitelist = $whitelist;
    }

    public function isBlacklist()
    {
        return $this->blacklist;
    }

    public function setBlacklist($blacklist)
    {
        $this->blacklist = $blacklist;
    }

    public function getSpamscore()
    {
        return $this->spamscore;
    }

    public function setSpamscore($spamscore)
    {
        $this->spamscore = $spamscore;
    }

    public function isCheckedbefore()
    {
        return $this->checkedbefore;
    }

    public function setCheckedbefore($checkedbefore)
    {
        $this->checkedbefore = $checkedbefore;
    }

    public function isSpam()
    {
        return $this->spam;
    }

    public function setSpam($spam)
    {
        $this->spam = $spam;
    }

    public function getReasons()
    {
        return $this->reasons;
    }

    public function addReasons(array $reasons)
    {
        $this->reasons = array_merge($this->reasons, $reasons);
    }

    public function getScoreLog()
    {
        return $this->scoreLog;
    }

    public function setScoreLog($scoreLog)
    {
        $this->scoreLog = $scoreLog;
    }
}
