<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'antispam:agent:deploy', description: 'Deploy agent to hosting server via SSH')]
class AgentDeployCommand extends Command
{
    private $em;
    private $ssh;

    public function __construct(EntityManagerInterface $em, SshService $ssh)
    {
        parent::__construct();
        $this->em = $em;
        $this->ssh = $ssh;
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

        $output->writeln('Deploying agent to ' . $account->getSshHost() . '...');

        try {
            $result = $this->ssh->deployAgent($account);
            $account->setAgentDeployed(true);
            $this->em->flush();
            $output->writeln('<info>Agent deployed successfully</info>');
            $output->writeln(json_encode($result, JSON_PRETTY_PRINT));
        } catch (\Exception $e) {
            $output->writeln('<error>Deploy failed: ' . $e->getMessage() . '</error>');
            return 1;
        }

        return 0;
    }
}
