<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'antispam:agent:sync', description: 'Sync blacklist / whitelist / DNSBL rules to remote agent')]
class AgentSyncCommand extends Command
{
    private $em;
    private $ssh;
    private $rulesExporter;

    public function __construct(EntityManagerInterface $em, SshService $ssh, AgentRulesExporter $rulesExporter)
    {
        parent::__construct();
        $this->em = $em;
        $this->ssh = $ssh;
        $this->rulesExporter = $rulesExporter;
    }

    protected function configure(): void
    {
        $this->addArgument('accountId', InputArgument::REQUIRED, 'Account ID');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $account = $this->em->getRepository(Account::class)->find($input->getArgument('accountId'));
        if (!$account || !$account->isSsh()) {
            $output->writeln('<error>Account not found or not SSH type</error>');
            return 1;
        }

        $output->writeln('Syncing rules for ' . $account->getEmail() . '...');

        $rules = $this->rulesExporter->export($account->getEmail());
        $output->writeln(sprintf(
            'Rules: %d wl, %d email-wl, %d bl, %d email-bl, %d dnsbl',
            count($rules['whitelist']), count($rules['email_whitelist']),
            count($rules['blacklist']), count($rules['email_blacklist']),
            count($rules['dnsbl'])
        ));

        try {
            $result = $this->ssh->syncRules($account, json_encode($rules));
            if (($result['success'] ?? null) !== true) {
                $output->writeln('<error>Sync failed: ' . ($result['error'] ?? 'unknown error') . '</error>');
                return 1;
            }
            $output->writeln('<info>Rules synced successfully</info>');
            if (!empty($result['agent_warning'])) {
                $output->writeln('<comment>' . $result['agent_warning'] . '</comment>');
            }
            $output->writeln(json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        } catch (\Exception $e) {
            $output->writeln('<error>Sync failed: ' . $e->getMessage() . '</error>');
            return 1;
        }
        return 0;
    }
}
