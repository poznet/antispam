<?php

namespace AntispamBundle\Command;

use AntispamBundle\Event\MessageEvent;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class AntispamGoCommand extends ContainerAwareCommand
{
    protected function configure()
    {
        $this
            ->setName('antispam:go')
            ->setDescription('checking e-mails')

        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $inbox=$this->getContainer()->get('antispam.inbox');
        $messages=$inbox->getInbox();
        $dispatcher = $this->getContainer()->get('event_dispatcher');
        $config= $this->getContainer()->get('configuration');

        foreach($messages as $msg) {
            $event = new MessageEvent($msg,$config->get('email'));
            $dispatcher->dispatch('antispam.check.message', $event);
        }


        $output->writeln('Checked '.count($messages).' messages');
    }

}
