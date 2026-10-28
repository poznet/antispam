<?php

namespace AntispamBundle\Services;

use Ddeboer\Imap\ConnectionInterface;

class InboxService
{
    private $connection;
    private $mailbox;
    private $spamboxname = 'SPAM';
    private $quarantineboxname = 'QUARANTINE';

    public function __construct(ConnectionService $connection)
    {
        $this->connection = $connection;
    }

    public function getInbox($name = 'INBOX', $condition = null)
    {
        $connection = $this->connection->getConnection();
        $this->mailbox = $connection->getMailbox($name);
        $messages = $this->mailbox->getMessages($condition);
        return $messages;
    }

    public function getMessage($id)
    {
        return $this->mailbox->getMessage($id);
    }

    /**
     * Permanently removes messages flagged as deleted - IMAP "move" leaves
     * the original in the source folder until the mailbox is expunged.
     */
    public function expunge()
    {
        $this->connection->getConnection()->expunge();
    }

    /**
     * @param ConnectionInterface|null $connection mailbox to look in; null = the legacy mailbox
     */
    public function getSpamFolder(?ConnectionInterface $connection = null)
    {
        return $this->getOrCreateFolder($this->spamboxname, $connection);
    }

    public function getSpamFolderName()
    {
        return $this->spamboxname;
    }

    /**
     * Returns (creating if needed) the quarantine folder used for messages
     * whose score is suspicious but below the spam threshold.
     */
    public function getQuarantineFolder(?ConnectionInterface $connection = null)
    {
        return $this->getOrCreateFolder($this->quarantineboxname, $connection);
    }

    public function getQuarantineFolderName()
    {
        return $this->quarantineboxname;
    }

    private function getOrCreateFolder($name, ?ConnectionInterface $connection = null)
    {
        $connection = $connection ?? $this->connection->getConnection();
        if (!$connection->hasMailbox($name)) {
            $connection->createMailbox($name);
        }
        return $connection->getMailbox($name);
    }
}
