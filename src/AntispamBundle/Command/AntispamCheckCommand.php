<?php

namespace AntispamBundle\Command;

use AntispamBundle\Event\CheckEvent;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

#[AsCommand(name: 'antispam:check', description: 'Checks antispam configuration')]
class AntispamCheckCommand extends Command
{
    private $dispatcher;

    public function __construct(EventDispatcherInterface $dispatcher)
    {
        $this->dispatcher = $dispatcher;
        parent::__construct();
    }


    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $event = new CheckEvent();
        $this->dispatcher->dispatch($event, 'antispam.check.config');

        if($event->getStatus() === true) {
            $output->writeln('<info>All OK</info>');
            return Command::SUCCESS;
        } else {
            $output->writeln('<error>Error:</error>');
            foreach ($event->getMessages() as $msg) {
                $output->writeln('  - ' . $msg);
            }
            return Command::FAILURE;
        }
    }
}
