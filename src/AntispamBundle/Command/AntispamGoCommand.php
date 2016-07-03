<?php

namespace AntispamBundle\Command;

use AntispamBundle\Event\MessageEvent;
use Ddeboer\Imap\Exception\Exception;
use Ddeboer\Imap\Exception\MessageUnsupportedEncodeException;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class AntispamGoCommand extends ContainerAwareCommand
{
    private $raport=array('whitelist'=>0,'checkedbefore'=>0,'blacklist'=>0,'delete'=>0);
    protected function configure()
    {
        $this
            ->setName('antispam:go')
            ->setDescription('checking e-mails')

        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {

        try {

        $inbox=$this->getContainer()->get('antispam.inbox');
        $messages = $inbox->getInbox();
        $dispatcher = $this->getContainer()->get('event_dispatcher');
        $config= $this->getContainer()->get('configuration');
        $checked=0;

        foreach($messages as $msg) {
            $checked++;
            $event = new MessageEvent($msg,$config->get('email'));
            $dispatcher->dispatch('antispam.check.message', $event);


            if($event->isCheckedbefore())  $this->raport['checkedbefore']++;
            if($event->isWhitelist())  $this->raport['whitelist']++;
            if($event->isBlacklist()) $this->raport['blacklist']++;
            if($event->isDelete()) $this->raport['delete']++;
        }

        }catch(MessageUnsupportedEncodeException $e){

        }


        $output->writeln('All  messages :'.count($messages).' ');
        $output->writeln('Message precessed :'.$checked.' ');
        $output->writeln('Checked before / skipped : '.$this->raport['checkedbefore'].' ');
        $output->writeln('Whitelisted : '.$this->raport['whitelist'].' ');
        $output->writeln('Blacklisted : '.$this->raport['blacklist'].' ');
        $output->writeln('Deleted/Moved : '.$this->raport['blacklist'].' ');

    }

}
