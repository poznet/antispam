<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 17.06.16
 * Time: 23:11
 */

namespace AntispamBundle\Services;

use Ddeboer\Imap\Server;
use Ddeboer\Imap\Mailbox;

class InboxService
{
    private $connection;
    private $mailbox;

    public function __construct(ConnectionService $connection)
    {
        $this->connection=$connection;
    }


    public function getInbox($name='INBOX'){
        $connection=$this->connection->getConnection();
        $this->mailbox = $connection->getMailbox($name);
        $messages = $this->mailbox->getMessages();
        return $messages;
    }

    public function getMessage($id){
        return $this->mailbox->getMessage($id);
    }

    
}