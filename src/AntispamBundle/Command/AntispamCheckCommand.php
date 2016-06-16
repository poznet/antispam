<?php

namespace AntispamBundle\Command;

use AntispamBundle\Event\CheckEvent;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class AntispamCheckCommand extends ContainerAwareCommand
{
    protected function configure()
    {
        $this
            ->setName('antispam:check')
            ->setDescription('checks config')

        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $event=new CheckEvent();
        $dispatcher = $this->getContainer()->get('event_dispatcher');
        $dispatcher->dispatch('antispam.check.config', $event);
        if($event->getStatus()===true) {
            $output->writeln('All OK');
        }else{
            $output->writeln('Error:');
            foreach ($event->getMessages() as $msg) {
                $output->writeln($msg);
            }
        }

    }

}
