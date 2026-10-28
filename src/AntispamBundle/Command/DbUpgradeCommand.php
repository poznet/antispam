<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\Database\DatabaseState;
use AntispamBundle\Services\Database\DatabaseUpgrader;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Logger\ConsoleLogger;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Upgrades the database schema to this release - the Docker entrypoint runs it
 * at every boot (RUN_MIGRATIONS=true). Idempotent; see docs/migrations.md.
 *
 *     php bin/console antispam:db:upgrade            # fresh / legacy / migrated, see DatabaseUpgrader
 *     php bin/console antispam:db:upgrade --dry-run  # show the plan, change nothing
 *
 * Exit codes: 0 = database is up to date; 1 = failed (database unreachable,
 * a migration failed, lock timeout); 2 = done, but the entities still differ
 * from the database (an entity change without a migration) or the database
 * has migrations this image does not know (it is newer than the image).
 */
#[AsCommand(name: 'antispam:db:upgrade', description: 'Create or upgrade the database schema (Doctrine Migrations; adopts installs made by schema:update)')]
class DbUpgradeCommand extends Command
{
    public const EXIT_WARNINGS = 2;

    public function __construct(private DatabaseUpgrader $upgrader)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Show what would be done without changing the database')
            ->addOption('lock-timeout', null, InputOption::VALUE_REQUIRED, 'Seconds to wait for a concurrent upgrade (MySQL GET_LOCK)', '600');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $dryRun = (bool)$input->getOption('dry-run');
        $this->upgrader->setLogger(new ConsoleLogger($output));

        $locked = false;
        try {
            if (!$dryRun) {
                if (!$this->upgrader->lock((int)$input->getOption('lock-timeout'))) {
                    $output->writeln('<error>[db:upgrade] Another upgrade holds the lock - timed out waiting for it.</error>');

                    return Command::FAILURE;
                }
                $locked = true;
            }

            return $this->upgrade($output, $dryRun);
        } catch (\Throwable $e) {
            $output->writeln(sprintf('<error>[db:upgrade] FAILED: %s: %s</error>', (new \ReflectionClass($e))->getShortName(), $e->getMessage()));
            $output->writeln('[db:upgrade] The database may be partially upgraded. Check with: php bin/console doctrine:migrations:status');

            return Command::FAILURE;
        } finally {
            if ($locked) {
                try {
                    $this->upgrader->unlock();
                } catch (\Throwable) {
                    // the connection is gone; MySQL releases the lock with it
                }
            }
        }
    }

    private function upgrade(OutputInterface $output, bool $dryRun): int
    {
        $state = $this->upgrader->inspect();
        $prefix = $dryRun ? '[db:upgrade] (dry run) ' : '[db:upgrade] ';
        $output->writeln(sprintf('%sDatabase state: %s (%d antispam table(s), %d migration(s) recorded, %d pending).',
            $prefix, $state->state, count($state->antispamTables), count($state->executed), count($state->pending)));
        if ($state->foreignTables !== []) {
            $output->writeln(sprintf('%sTables not in the entity mapping (left alone): %s', $prefix, implode(', ', $state->foreignTables)));
        }

        $warnings = 0;
        if ($state->unknownExecuted !== []) {
            $warnings++;
            $output->writeln(sprintf('<comment>%sWARNING: the database has %d migration(s) this image does not ship (%s) - it was upgraded by a newer release. Deploy that release (downgrades are not supported).</comment>',
                $prefix, count($state->unknownExecuted), implode(', ', $state->unknownExecuted)));
        }

        switch ($state->state) {
            case DatabaseState::FRESH:
                $output->writeln($prefix . 'Empty database: creating the schema by running all migrations.');
                $this->runMigrations($output, $dryRun, $state->pending, $prefix);
                break;

            case DatabaseState::LEGACY:
                $output->writeln($prefix . 'Existing install without migration history (made by doctrine:schema:update): adopting it.');
                $plan = $this->upgrader->schemaUpdatePlan();
                $output->writeln(sprintf('%sStep 1/3: schema:update to the current entities - %d statement(s).', $prefix, count($plan['run'])));
                foreach ($plan['run'] as $sql) {
                    $output->writeln(($this->isDestructive($sql) ? '  [DROPS DATA] ' : '  ') . self::oneLine($sql), OutputInterface::OUTPUT_RAW);
                }
                foreach ($plan['skipped'] as $sql) {
                    $output->writeln('  [skipped, table kept] ' . self::oneLine($sql), OutputInterface::OUTPUT_RAW);
                }
                if (!$dryRun) {
                    $this->upgrader->updateSchema();
                }
                $output->writeln(sprintf('%sStep 2/3: marking %d migration(s) as executed (doctrine:migrations:version --add --all): %s',
                    $prefix, count($state->pending), implode(', ', $state->pending) ?: '-'));
                if (!$dryRun) {
                    $this->upgrader->markAllExecuted();
                }
                $output->writeln($prefix . 'Step 3/3: migrate.');
                $this->runMigrations($output, $dryRun, $dryRun ? [] : $this->upgrader->pendingMigrations(), $prefix);
                break;

            default:
                $this->runMigrations($output, $dryRun, $state->pending, $prefix);
        }

        if (!$dryRun) {
            $drift = $this->upgrader->pendingSchemaChanges();
            if ($drift !== []) {
                $warnings++;
                $output->writeln(sprintf('<comment>%sWARNING: the entities still differ from the database (%d statement(s), e.g. %s). An entity change has no migration - generate one (docs/migrations.md).</comment>',
                    $prefix, count($drift), mb_substr(self::oneLine($drift[0]), 0, 160)));
            }
        }

        $output->writeln($prefix . ($warnings > 0 ? sprintf('Finished with %d warning(s).', $warnings) : ($dryRun ? 'Plan complete, nothing changed.' : 'Database is up to date.')));

        return $warnings > 0 ? self::EXIT_WARNINGS : Command::SUCCESS;
    }

    /** @param string[] $pending */
    private function runMigrations(OutputInterface $output, bool $dryRun, array $pending, string $prefix): void
    {
        if ($pending === []) {
            $output->writeln($prefix . 'No pending migrations.');

            return;
        }
        $output->writeln(sprintf('%s%s %d migration(s): %s', $prefix, $dryRun ? 'Would run' : 'Running', count($pending), implode(', ', $pending)));
        if (!$dryRun) {
            $done = $this->upgrader->migrate();
            $output->writeln(sprintf('%sExecuted %d migration(s).', $prefix, count($done)));
        }
    }

    /** Drops a column (indexes / keys are rebuilt, not data). */
    private function isDestructive(string $sql): bool
    {
        return (bool)preg_match('/\bDROP\b(?!\s+(INDEX|FOREIGN KEY|PRIMARY KEY|CONSTRAINT))/i', $sql);
    }

    private static function oneLine(string $sql): string
    {
        return trim(preg_replace('/\s+/', ' ', $sql));
    }
}
