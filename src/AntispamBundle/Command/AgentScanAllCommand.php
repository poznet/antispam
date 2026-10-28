<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AccountScanner;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\Jobs\JobQueue;
use AntispamBundle\Services\ScanLockedException;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Scans every mailbox: SSH accounts through their agent, IMAP accounts and
 * the legacy mailbox from the "E-mail" settings through the IMAP pipeline.
 *
 * A mailbox that is being scanned right now (a background scan job started
 * from the panel, or the agent's own lock) is skipped, not counted as an
 * error. An IMAP mailbox gets at most --max-seconds per run: a huge INBOX
 * (first scan) is continued from its cursor on the next run.
 */
#[AsCommand(name: 'antispam:agent:scan-all', description: 'Run spam scan on all configured accounts')]
class AgentScanAllCommand extends Command
{
    const DEFAULT_MAX_SECONDS = 600;

    public function __construct(
        private EntityManagerInterface $em,
        private AccountScanner $scanner,
        private ImapScanService $imapScan,
        private ?JobQueue $jobs = null,
        #[Autowire('%env(default::SCAN_MAX_SECONDS)%')] private ?string $envMaxSeconds = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('max-seconds', null, InputOption::VALUE_REQUIRED, 'Time budget of one IMAP mailbox per run; the rest is scanned on the next run (0 = no limit; default env SCAN_MAX_SECONDS or ' . self::DEFAULT_MAX_SECONDS . ')');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $maxSeconds = $input->getOption('max-seconds')
            ?? ($this->envMaxSeconds !== null && $this->envMaxSeconds !== '' ? $this->envMaxSeconds : (string)self::DEFAULT_MAX_SECONDS);
        if (!is_numeric($maxSeconds) || (int)$maxSeconds < 0) {
            $output->writeln('<error>--max-seconds must be a number >= 0</error>');
            return Command::INVALID;
        }
        $maxSeconds = (int)$maxSeconds;

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

            if ($account->isSsh() && !$account->getAgentDeployed()) {
                $output->writeln('<comment>skipped (agent not deployed)</comment>');
                continue;
            }
            if ($this->jobs && $this->jobs->hasActive(BackgroundJob::TYPE_ACCOUNT_SCAN, (int)$account->getId())) {
                $output->writeln('<comment>skipped (scan queued from the panel - see Zadania w tle)</comment>');
                continue;
            }
            try {
                $result = $this->scanner->scan($account, null, $maxSeconds > 0 ? microtime(true) + $maxSeconds : null);
                $this->scanner->finish($account, $result);
                $this->writeResult($output, $result);
            } catch (ScanLockedException $e) {
                $output->writeln('<comment>skipped (' . $e->getMessage() . ')</comment>');
            } catch (\Throwable $e) {
                $output->writeln('<error>FAILED: ' . $e->getMessage() . '</error>');
                $errors++;
            }
        }

        if ($legacy) {
            $output->write('IMAP (ustawienia E-mail): ');
            try {
                $this->writeResult($output, $this->imapScan->scanLegacy());
            } catch (ScanLockedException $e) {
                $output->writeln('<comment>skipped (' . $e->getMessage() . ')</comment>');
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
            '<info>OK</info> - %d total, %d new, %d spam, %d quarantine, %d whitelisted%s',
            $result['total'] ?? 0,
            $result['checked'] ?? 0,
            $result['moved_to_spam'] ?? 0,
            $result['quarantined'] ?? 0,
            $result['whitelisted'] ?? 0,
            !empty($result['remaining']) ? sprintf(', %d left for the next run%s', $result['remaining'], !empty($result['initial']) ? ' (initial scan)' : '') : ''
        ));
        foreach ((array)($result['errors'] ?? []) as $error) {
            $output->writeln('  <comment>' . $error . '</comment>');
        }
    }
}
