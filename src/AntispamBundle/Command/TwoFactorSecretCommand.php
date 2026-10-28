<?php

namespace AntispamBundle\Command;

use AntispamBundle\Security\TwoFactor\Totp;
use AntispamBundle\Security\TwoFactor\TwoFactorService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Prints a new TOTP secret for the environment admin (ADMIN_TOTP_SECRET) and
 * the otpauth:// URI to add to an authenticator app. Nothing is stored.
 */
#[AsCommand(name: 'antispam:2fa:secret', description: 'Generate a TOTP secret for ADMIN_TOTP_SECRET (env admin 2FA)')]
class TwoFactorSecretCommand extends Command
{
    public function __construct(#[Autowire('%env(ADMIN_USER)%')] private string $adminUser)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('check', null, InputOption::VALUE_REQUIRED, 'Print the current code of this secret instead (verify the app shows the same)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $check = $input->getOption('check');
        if ($check !== null) {
            if (!Totp::isValidSecret($check)) {
                $output->writeln('<error>Not a base32 secret of at least 16 characters</error>');
                return 1;
            }
            $output->writeln(Totp::code($check, Totp::counterAt()));
            return 0;
        }

        $secret = Totp::generateSecret();
        $output->writeln('ADMIN_TOTP_SECRET=' . $secret);
        $output->writeln('');
        $output->writeln('Add it to an authenticator app (manual entry, or a QR code of this URI):');
        $output->writeln(Totp::provisioningUri($secret, $this->adminUser !== '' ? $this->adminUser : 'admin', TwoFactorService::ISSUER));
        $output->writeln('');
        $output->writeln('<comment>Set the variable in the server configuration and restart; keep it secret (it is the second factor).</comment>');
        return 0;
    }
}
