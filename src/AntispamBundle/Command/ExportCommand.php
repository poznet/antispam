<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\Backup\BackupExporter;
use AntispamBundle\Services\Backup\BackupFormat;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Configuration backup: settings, list rules, DNSBL providers, accounts and
 * users as one versioned JSON (or a ZIP holding it). See docs/backup.md.
 *
 *     php bin/console antispam:export --output=backup.json
 *     php bin/console antispam:export --output=backup.zip --include-secrets
 *     php bin/console antispam:export > backup.json          # JSON on stdout
 */
#[AsCommand(name: 'antispam:export', description: 'Export the configuration (settings, rules, DNSBL, accounts, users) to a JSON/ZIP backup')]
class ExportCommand extends Command
{
    public function __construct(private BackupExporter $exporter)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Target file (.json or .zip); omitted = JSON on stdout')
            ->addOption('include-secrets', null, InputOption::VALUE_NONE, 'Include passwords, API keys and password hashes (encrypted with this instance\'s APP_SECRET)')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Overwrite an existing output file');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $err = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        $file = $input->getOption('output');
        $withSecrets = (bool)$input->getOption('include-secrets');

        if ($file !== null && is_file($file) && !$input->getOption('force')) {
            $err->writeln('<error>' . $file . ' already exists - use --force to overwrite it.</error>');
            return Command::FAILURE;
        }

        $data = $this->exporter->export($withSecrets);
        $json = BackupFormat::encode($data);

        if ($file === null) {
            $output->write($json, false, OutputInterface::OUTPUT_RAW);
        } else {
            $content = strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'zip' ? BackupFormat::zip($json) : $json;
            // Not readable by other users of the host: the file names every mailbox (and maybe secrets).
            $old = umask(0077);
            try {
                if (file_put_contents($file, $content) === false) {
                    $err->writeln('<error>Cannot write ' . $file . '</error>');
                    return Command::FAILURE;
                }
            } finally {
                umask($old);
            }
            @chmod($file, 0600);
            $err->writeln(sprintf(
                '<info>Exported</info> %d setting(s), %d rule(s), %d DNSBL provider(s), %d account(s), %d user(s) to %s',
                count((array)$data['settings']['config']) + count((array)$data['settings']['lists']),
                array_sum(array_map('count', $data['rules'])),
                count($data['dnsbl']),
                count($data['accounts']),
                count($data['users']),
                $file
            ));
        }

        foreach ($this->exporter->getWarnings() as $warning) {
            $err->writeln('<comment>' . $warning . '</comment>');
        }
        if ($withSecrets) {
            $err->writeln('<comment>WARNING: the backup contains secrets (passwords, API keys, password hashes), encrypted with a key derived from APP_SECRET.'
                . ' Anyone with this file AND the APP_SECRET can read them - store it like a password.'
                . ' The target instance needs the same APP_SECRET, otherwise the secrets are skipped on import.</comment>');
        } else {
            $err->writeln('<comment>Secrets are not included (passwords, API keys) - use --include-secrets to move them too.</comment>');
        }

        return Command::SUCCESS;
    }
}
