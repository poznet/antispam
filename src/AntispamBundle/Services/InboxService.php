<?php

namespace AntispamBundle\Services;

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

    public function getSpamFolder()
    {
        return $this->getOrCreateFolder($this->spamboxname);
    }

    public function getSpamFolderName()
    {
        return $this->spamboxname;
    }

    /**
     * Returns (creating if needed) the quarantine folder used for messages
     * whose score is suspicious but below the spam threshold.
     */
    public function getQuarantineFolder()
    {
        return $this->getOrCreateFolder($this->quarantineboxname);
    }

    public function getQuarantineFolderName()
    {
        return $this->quarantineboxname;
    }

    private function getOrCreateFolder($name)
    {
        $connection = $this->connection->getConnection();
        if (!$connection->hasMailbox($name)) {
            $connection->createMailbox($name);
        }
        return $connection->getMailbox($name);
    }
}
