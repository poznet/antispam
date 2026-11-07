<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\User;
use AntispamBundle\Security\YubiKey\YubiKeyService;
use AntispamBundle\Services\AuditLogger;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Recovery from a lost YubiKey without the panel - above all for the built-in
 * ADMIN_USER account: lists or removes the keys of a login (database user or
 * the env admin). --list only prints them.
 */
#[AsCommand(name: 'antispam:yubikey:reset', description: 'List / remove the registered YubiKeys of a login (lost key recovery, also for ADMIN_USER)')]
class YubiKeyResetCommand extends Command
{
    public function __construct(
        private YubiKeyService $yubiKeys,
        private EntityManagerInterface $em,
        #[Autowire('%env(ADMIN_USER)%')] private string $adminUser,
        private ?AuditLogger $audit = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('login', InputArgument::OPTIONAL, 'Login of the user (default: ADMIN_USER)')
            ->addOption('list', null, InputOption::VALUE_NONE, 'Only list the keys, remove nothing');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $login = (string)($input->getArgument('login') ?? $this->adminUser);
        if ($login === '') {
            $output->writeln('<error>Give a login (ADMIN_USER is not set)</error>');
            return 1;
        }
        $isEnvAdmin = $this->adminUser !== '' && hash_equals($this->adminUser, $login);
        $user = $isEnvAdmin ? null : $this->em->getRepository(User::class)->findOneBy(['username' => $login]);
        if (!$isEnvAdmin && !$user) {
            $output->writeln(sprintf('<error>No user "%s"</error>', $login));
            return 1;
        }

        $keys = $isEnvAdmin ? $this->yubiKeys->keysOfEnvAdmin($login) : $this->yubiKeys->keysOf($user);
        $output->writeln(sprintf('%s%s: %d key(s)', $login, $isEnvAdmin ? ' (ADMIN_USER)' : '', count($keys)));
        foreach ($keys as $key) {
            $output->writeln(sprintf('  %s  %s  added %s', $key->getPublicId(), $key->getName(), $key->getCreatedAt()->format('Y-m-d H:i')));
        }
        if ($input->getOption('list') || !$keys) {
            return 0;
        }

        $removed = $isEnvAdmin ? $this->yubiKeys->removeAllOfEnvAdmin($login) : $this->yubiKeys->removeAll($user);
        $this->audit?->log('auth.2fa_reset', targetType: 'user', targetId: $user?->getId(), label: $login, actor: 'cli', actorType: \AntispamBundle\Entity\AuditLog::ACTOR_CLI,
            details: ['source' => 'cli', 'env_admin' => $isEnvAdmin, 'yubikeys_removed' => $removed]);
        $output->writeln(sprintf('<info>Removed %d key(s) of %s.</info>', $removed, $login));
        return 0;
    }
}
