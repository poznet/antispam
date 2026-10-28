<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Scans every mailbox: SSH accounts through their agent, IMAP accounts and
 * the legacy mailbox from the "E-mail" settings through the IMAP pipeline.
 */
#[AsCommand(name: 'antispam:agent:scan-all', description: 'Run spam scan on all configured accounts')]
class AgentScanAllCommand extends Command
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


    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $accounts = $this->em->getRepository(Account::class)->findAll();
        $legacy = $this->imapScan->isLegacyConfigured();

        if (empty($accounts) && !$legacy) {
            $output->writeln('<comment>No accounts configured</comment>');
            return 0;
        }

        $output->writeln('Scanning ' . (count($accounts) + ($legacy ? 1 : 0)) . ' mailbox(es)...');
        $errors = 0;

        foreach ($accounts as $account) {
            $output->write($account->getEmail() . ' (' . $account->getConnectionType() . '): ');

            try {
                if ($account->isSsh()) {
                    if (!$account->getAgentDeployed()) {
                        $output->writeln('<comment>skipped (agent not deployed)</comment>');
                        continue;
                    }
                    $result = $this->ssh->runScan($account);
                    if (!isset($result['total'])) {
                        throw new \RuntimeException(substr((string)($result['error'] ?? 'invalid agent response'), 0, 300));
                    }
                } else {
                    $result = $this->imapScan->scanAccount($account);
                }

                $account->setLastScanAt(new \DateTime());
                $account->setLastScanResult(json_encode($result));
                $this->em->flush();

                $this->writeResult($output, $result);
            } catch (\Throwable $e) {
                $output->writeln('<error>FAILED: ' . $e->getMessage() . '</error>');
                $errors++;
            }
        }

        if ($legacy) {
            $output->write('IMAP (ustawienia E-mail): ');
            try {
                $this->writeResult($output, $this->imapScan->scanLegacy());
            } catch (\Throwable $e) {
                $output->writeln('<error>FAILED: ' . $e->getMessage() . '</error>');
                $errors++;
            }
        }

        return $errors > 0 ? 1 : 0;
    }

    private function writeResult(OutputInterface $output, array $result)
    {
        $output->writeln(sprintf(
            '<info>OK</info> - %d total, %d new, %d spam, %d quarantine, %d whitelisted',
            $result['total'] ?? 0,
            $result['checked'] ?? 0,
            $result['moved_to_spam'] ?? 0,
            $result['quarantined'] ?? 0,
            $result['whitelisted'] ?? 0
        ));
        foreach ((array)($result['errors'] ?? []) as $error) {
            $output->writeln('  <comment>' . $error . '</comment>');
        }
    }
}
