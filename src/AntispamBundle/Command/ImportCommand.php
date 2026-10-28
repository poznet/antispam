<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\Backup\BackupFormat;
use AntispamBundle\Services\Backup\BackupImporter;
use AntispamBundle\Services\Backup\ImportReport;
use AntispamBundle\Services\Backup\InvalidBackupException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Restores a backup made by `antispam:export`. See docs/backup.md.
 *
 *     php bin/console antispam:import backup.json --dry-run
 *     php bin/console antispam:import backup.json
 *     php bin/console antispam:import backup.zip --only=rules,dnsbl
 *     php bin/console antispam:import backup.json --mode=replace --confirm-replace
 */
#[AsCommand(name: 'antispam:import', description: 'Import a configuration backup made by antispam:export (merge or replace)')]
class ImportCommand extends Command
{
    public function __construct(private BackupImporter $importer)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('file', InputArgument::REQUIRED, 'Backup file (.json or .zip)')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Only show what would change, write nothing')
            ->addOption('mode', null, InputOption::VALUE_REQUIRED, 'merge (add/update, keep the rest) or replace (also delete what is not in the file)', BackupImporter::MODE_MERGE)
            ->addOption('confirm-replace', null, InputOption::VALUE_NONE, 'Required with --mode=replace (deletes records missing from the file)')
            ->addOption('only', null, InputOption::VALUE_REQUIRED, 'Comma-separated sections: ' . implode(',', BackupFormat::SECTIONS));
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $mode = (string)$input->getOption('mode');
        $dryRun = (bool)$input->getOption('dry-run');
        if (!in_array($mode, BackupImporter::MODES, true)) {
            $output->writeln('<error>--mode must be merge or replace.</error>');
            return Command::INVALID;
        }
        if ($mode === BackupImporter::MODE_REPLACE && !$dryRun && !$input->getOption('confirm-replace')) {
            $output->writeln('<error>--mode=replace deletes settings, rules, DNSBL providers, accounts and users that are not in the file.'
                . ' Run it with --dry-run first, then add --confirm-replace.</error>');
            return Command::INVALID;
        }

        try {
            $sections = BackupFormat::parseOnly($input->getOption('only'));
            $data = BackupFormat::readFile((string)$input->getArgument('file'));
            $report = $this->importer->import($data, $sections, $mode, $dryRun);
        } catch (InvalidBackupException $e) {
            $output->writeln('<error>Invalid backup: ' . $e->getMessage() . '</error>');
            return Command::FAILURE;
        } catch (\Throwable $e) {
            $output->writeln('<error>Import failed, nothing was changed: ' . $e->getMessage() . '</error>');
            return Command::FAILURE;
        }

        self::printReport($output, $report);

        return Command::SUCCESS;
    }

    public static function printReport(OutputInterface $output, ImportReport $report): void
    {
        $meta = $report->meta;
        $output->writeln(sprintf(
            'Backup: schema %s, app version %s, exported %s, secrets: %s',
            $meta['schema_version'] ?? '?',
            $meta['app_version'] ?? 'unknown',
            $meta['exported_at'] ?? '?',
            !empty($meta['include_secrets']) ? 'yes' : 'no'
        ));
        $output->writeln(sprintf('Mode: %s%s', $report->mode, $report->dryRun ? ' (dry run - nothing written)' : ''));

        $table = new Table($output);
        $table->setHeaders(array_merge(['Section'], ImportReport::ACTIONS));
        foreach ($report->getCounts() as $section => $counts) {
            $table->addRow(array_merge([$section], array_values($counts)));
        }
        $table->render();

        foreach ($report->getWarnings() as $warning) {
            $output->writeln('<comment>! ' . $warning . '</comment>');
        }
        if ($report->dryRun) {
            $output->writeln($report->hasChanges() ? 'Run again without --dry-run to apply.' : 'Nothing to change.');
        } else {
            $output->writeln('<info>Import finished.</info> Push rules and settings to each SSH agent: `antispam:agent:sync <accountId>` (or Konta → Synchronizuj).');
        }
    }
}
