<?php

namespace AntispamBundle\Command;

use AntispamBundle\Event\CheckEvent;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class AntispamCheckCommand extends Command
{
    protected static $defaultName = 'antispam:check';

    private $dispatcher;

    public function __construct(EventDispatcherInterface $dispatcher)
    {
        $this->dispatcher = $dispatcher;
        parent::__construct();
    }

    protected function configure()
    {
        $this
            ->setDescription('Checks antispam configuration');
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
