<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\ImapScanService;
use Ddeboer\Imap\Exception\AbstractException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'antispam:go', description: 'Checking e-mails for spam')]
class AntispamGoCommand extends Command
{
    private $imapScan;

    public function __construct(ImapScanService $imapScan)
    {
        $this->imapScan = $imapScan;

        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $stats = $this->imapScan->scanLegacy();
        } catch (AbstractException $e) {
            $output->writeln('<error>IMAP error: ' . $e->getMessage() . '</error>');
            return Command::FAILURE;
        }

        $output->writeln('All messages: ' . $stats['total']);
        $output->writeln('Messages processed: ' . $stats['checked']);
        $output->writeln('Checked before / skipped: ' . $stats['skipped']);
        $output->writeln('Whitelisted: ' . $stats['whitelisted']);
        $output->writeln('Blacklisted: ' . $stats['blacklisted']);
        $output->writeln('Moved to spam / deleted: ' . $stats['moved_to_spam']);
        $output->writeln('Quarantined: ' . $stats['quarantined']);
        foreach ($stats['errors'] as $error) {
            $output->writeln('<comment>Error: ' . $error . '</comment>');
        }

        return Command::SUCCESS;
    }
}
