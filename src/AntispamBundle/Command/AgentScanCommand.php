<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class AgentScanCommand extends Command
{
    protected static $defaultName = 'antispam:agent:scan';

    private $em;
    private $ssh;

    public function __construct(EntityManagerInterface $em, SshService $ssh)
    {
        parent::__construct();
        $this->em = $em;
        $this->ssh = $ssh;
    }

    protected function configure()
    {
        $this->setDescription('Run spam scan on an account')
             ->addArgument('accountId', InputArgument::REQUIRED, 'Account ID');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $account = $this->em->getRepository('AntispamBundle:Account')->find($input->getArgument('accountId'));
        if (!$account) {
            $output->writeln('<error>Account not found</error>');
            return 1;
        }

        $output->writeln('Scanning ' . $account->getEmail() . ' (' . $account->getConnectionType() . ')...');

        try {
            if ($account->isSsh()) {
                $result = $this->ssh->runScan($account);
            } else {
                $output->writeln('<comment>IMAP scan - use antispam:go for legacy IMAP scanning</comment>');
                return 0;
            }

            $account->setLastScanAt(new \DateTime());
            $account->setLastScanResult(json_encode($result));
            $this->em->flush();

            $output->writeln('<info>Scan completed:</info>');
            $output->writeln('  Total: ' . ($result['total'] ?? 0));
            $output->writeln('  Checked: ' . ($result['checked'] ?? 0));
            $output->writeln('  Skipped: ' . ($result['skipped'] ?? 0));
            $output->writeln('  Whitelisted: ' . ($result['whitelisted'] ?? 0));
            $output->writeln('  Blacklisted: ' . ($result['blacklisted'] ?? 0));
            $output->writeln('  Moved to spam: ' . ($result['moved_to_spam'] ?? 0));
        } catch (\Exception $e) {
            $output->writeln('<error>Scan failed: ' . $e->getMessage() . '</error>');
            return 1;
        }

        return 0;
    }
}
