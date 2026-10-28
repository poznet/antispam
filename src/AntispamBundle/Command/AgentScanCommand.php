<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'antispam:agent:scan', description: 'Run spam scan on an account')]
class AgentScanCommand extends Command
{
    private $em;
    private $ssh;
    private $imapScan;

    public function __construct(EntityManagerInterface $em, SshService $ssh, ImapScanService $imapScan)
    {
        parent::__construct();
        $this->em = $em;
        $this->ssh = $ssh;
        $this->imapScan = $imapScan;
    }

    protected function configure(): void
    {
        $this->addArgument('accountId', InputArgument::REQUIRED, 'Account ID');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $account = $this->em->getRepository(Account::class)->find($input->getArgument('accountId'));
        if (!$account) {
            $output->writeln('<error>Account not found</error>');
            return 1;
        }

        $output->writeln('Scanning ' . $account->getEmail() . ' (' . $account->getConnectionType() . ')...');

        try {
            if ($account->isSsh()) {
                $result = $this->ssh->runScan($account);
            } else {
                $result = $this->imapScan->scanAccount($account);
            }

            $account->markScanned($result);
            $this->em->flush();

            $output->writeln('<info>Scan completed:</info>');
            $output->writeln('  Total: ' . ($result['total'] ?? 0));
            $output->writeln('  Checked: ' . ($result['checked'] ?? 0));
            $output->writeln('  Skipped: ' . ($result['skipped'] ?? 0));
            $output->writeln('  Whitelisted: ' . ($result['whitelisted'] ?? 0));
            $output->writeln('  Blacklisted: ' . ($result['blacklisted'] ?? 0));
            $output->writeln('  Moved to spam: ' . ($result['moved_to_spam'] ?? 0));
            $output->writeln('  Quarantined: ' . ($result['quarantined'] ?? 0));
        } catch (\Throwable $e) {
            $output->writeln('<error>Scan failed: ' . $e->getMessage() . '</error>');
            return 1;
        }

        return 0;
    }
}
