<?php

namespace AntispamBundle\Command;

use AntispamBundle\Event\MessageEvent;
use Ddeboer\Imap\Exception\Exception;
use Ddeboer\Imap\Exception\MessageUnsupportedEncodeException;
use Poznet\ConfigBundle\Service\ConfigService;
use Psr\Container\ContainerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class AntispamGoCommand extends Command
{
    protected static $defaultName = 'antispam:go';

    private $raport = ['whitelist' => 0, 'checkedbefore' => 0, 'blacklist' => 0, 'delete' => 0];
    private $imap;
    private $dispatcher;
    private $config;

    /**
     * The inbox comes from a service locator because ConnectionService logs in
     * to IMAP as soon as it is built - resolving it eagerly would break
     * "app/console list" on installs without the legacy IMAP mailbox.
     */
    public function __construct(ContainerInterface $imap, EventDispatcherInterface $dispatcher, ConfigService $config)
    {
        $this->imap = $imap;
        $this->dispatcher = $dispatcher;
        $this->config = $config;

        parent::__construct();
    }

    protected function configure()
    {
        $this
            ->setDescription('Checking e-mails for spam');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $messages = $this->imap->get('antispam.inbox')->getInbox();
            $checked = 0;

            foreach($messages as $msg) {
                $checked++;
                $event = new MessageEvent($msg, $this->config->get('email'));
                $this->dispatcher->dispatch($event, 'antispam.check.message');

                if($event->isCheckedbefore())  $this->raport['checkedbefore']++;
                if($event->isWhitelist())  $this->raport['whitelist']++;
                if($event->isBlacklist()) $this->raport['blacklist']++;
                if($event->isDelete()) $this->raport['delete']++;
            }

        } catch(MessageUnsupportedEncodeException $e) {
            $output->writeln('<error>Error processing message: ' . $e->getMessage() . '</error>');
            return Command::FAILURE;
        }

        $output->writeln('All messages: ' . count($messages));
        $output->writeln('Messages processed: ' . $checked);
        $output->writeln('Checked before / skipped: ' . $this->raport['checkedbefore']);
        $output->writeln('Whitelisted: ' . $this->raport['whitelist']);
        $output->writeln('Blacklisted: ' . $this->raport['blacklist']);
        $output->writeln('Deleted/Moved: ' . $this->raport['delete']);

        return Command::SUCCESS;
    }
}
