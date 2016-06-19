<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 17.06.16
 * Time: 23:11
 */

namespace AntispamBundle\Services;



class InboxService
{
    private $connection;
    private $mailbox;
    private $spamboxname='SPAM';

    public function __construct(ConnectionService $connection)
    {
        $this->connection=$connection;
    }

    /**
     * Return the Inbox instance
     * @param string $name
     * @return mixed
     */
    public function getInbox($name='INBOX'){
        $connection=$this->connection->getConnection();
        $this->mailbox = $connection->getMailbox($name);
        $messages = $this->mailbox->getMessages();
        return $messages;
    }

    /**
     * Returns message of given id
     * @param $id
     * @return mixed
     */
    public function getMessage($id){
        return $this->mailbox->getMessage($id);
    }


    /**
     * Return spambox instance ( create one if not exists)
     * @return mixed
     */
    public function getSpamFolder(){
        $spambox=$this->spamboxname;
        $connection=$this->connection->getConnection();
        if (!$connection->hasMailbox($spambox)){
            $connection->createMailbox($spambox);
        }
        return  $connection->getMailbox($spambox);
    }

    /**
     * Return Spambox name
     * @return string
     */
    public function getSpamFolderName(){
        return $this->spamboxname;
    }


    
}