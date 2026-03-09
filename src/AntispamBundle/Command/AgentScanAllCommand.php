<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class AgentScanAllCommand extends Command
{
    protected static $defaultName = 'antispam:agent:scan-all';

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
        $this->setDescription('Run spam scan on all configured accounts');
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $accounts = $this->em->getRepository('AntispamBundle:Account')->findAll();

        if (empty($accounts)) {
            $output->writeln('<comment>No accounts configured</comment>');
            return 0;
        }

        $output->writeln('Scanning ' . count($accounts) . ' account(s)...');
        $errors = 0;

        foreach ($accounts as $account) {
            $output->write($account->getEmail() . ' (' . $account->getConnectionType() . '): ');

            try {
                if ($account->isSsh()) {
                    $result = $this->ssh->runScan($account);
                } else {
                    $output->writeln('<comment>skipped (IMAP - use antispam:go)</comment>');
                    continue;
                }

                $account->setLastScanAt(new \DateTime());
                $account->setLastScanResult(json_encode($result));
                $this->em->flush();

                $output->writeln('<info>OK</info> - '
                    . ($result['total'] ?? 0) . ' total, '
                    . ($result['moved_to_spam'] ?? 0) . ' spam');
            } catch (\Exception $e) {
                $output->writeln('<error>FAILED: ' . $e->getMessage() . '</error>');
                $errors++;
            }
        }

        return $errors > 0 ? 1 : 0;
    }
}
