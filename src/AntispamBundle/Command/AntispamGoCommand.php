<?php

namespace AntispamBundle\Command;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\InboxService;
use Ddeboer\Imap\Exception\AbstractException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

#[AsCommand(name: 'antispam:go', description: 'Checking e-mails for spam')]
class AntispamGoCommand extends Command
{
    private $inbox;
    private $dispatcher;
    private $config;

    public function __construct(InboxService $inbox, EventDispatcherInterface $dispatcher, ConfigService $config)
    {
        $this->inbox = $inbox;
        $this->dispatcher = $dispatcher;
        $this->config = $config;

        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $report = ['whitelist' => 0, 'checkedbefore' => 0, 'blacklist' => 0, 'delete' => 0];
        $checked = 0;

        try {
            $messages = $this->inbox->getInbox();
            foreach ($messages as $msg) {
                $checked++;
                $event = new MessageEvent($msg, $this->config->get('email'));
                $this->dispatcher->dispatch($event, 'antispam.check.message');

                if ($event->isCheckedbefore()) $report['checkedbefore']++;
                if ($event->isWhitelist()) $report['whitelist']++;
                if ($event->isBlacklist()) $report['blacklist']++;
                if ($event->isDelete()) $report['delete']++;
            }
            if ($report['delete'] > 0) {
                $this->inbox->expunge();
            }
        } catch (AbstractException $e) {
            $output->writeln('<error>IMAP error: ' . $e->getMessage() . '</error>');
            return Command::FAILURE;
        }

        $output->writeln('All messages: ' . count($messages));
        $output->writeln('Messages processed: ' . $checked);
        $output->writeln('Checked before / skipped: ' . $report['checkedbefore']);
        $output->writeln('Whitelisted: ' . $report['whitelist']);
        $output->writeln('Blacklisted: ' . $report['blacklist']);
        $output->writeln('Deleted/Moved: ' . $report['delete']);

        return Command::SUCCESS;
    }
}
