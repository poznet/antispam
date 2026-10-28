<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\Doctor\DoctorCheck;
use AntispamBundle\Services\Doctor\DoctorService;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Configuration sanity checks (see DoctorService and docs/backup.md#antispamdoctor).
 *
 *     php bin/console antispam:doctor            # exit 1 when any check fails
 *     php bin/console antispam:doctor --strict   # warnings fail too
 *     php bin/console antispam:doctor --format=json
 */
#[AsCommand(name: 'antispam:doctor', description: 'Check the configuration of this install (secrets, mail, https, schema, cron, accounts, PHP, disk)')]
class DoctorCommand extends Command
{
    private const LABELS = [
        DoctorCheck::OK => '<info>[ OK ]</info>',
        DoctorCheck::WARN => '<comment>[WARN]</comment>',
        DoctorCheck::FAIL => '<error>[FAIL]</error>',
        DoctorCheck::SKIP => '[ -- ]',
    ];

    public function __construct(private DoctorService $doctor)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('strict', null, InputOption::VALUE_NONE, 'Exit with 1 on warnings as well')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, 'text or json', 'text');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $checks = $this->doctor->run();
        $counts = array_fill_keys([DoctorCheck::OK, DoctorCheck::WARN, DoctorCheck::FAIL, DoctorCheck::SKIP], 0);
        foreach ($checks as $check) {
            $counts[$check->status]++;
        }
        $failed = $counts[DoctorCheck::FAIL] > 0 || ($input->getOption('strict') && $counts[DoctorCheck::WARN] > 0);

        if ($input->getOption('format') === 'json') {
            $output->writeln(json_encode([
                'ok' => !$failed,
                'counts' => $counts,
                'checks' => array_map(fn(DoctorCheck $c) => ['id' => $c->id, 'status' => $c->status, 'message' => $c->message, 'hint' => $c->hint], $checks),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

            return $failed ? Command::FAILURE : Command::SUCCESS;
        }

        foreach ($checks as $check) {
            $output->writeln(sprintf('%s %-17s %s', self::LABELS[$check->status], $check->id, $check->message));
            if ($check->hint !== '' && $check->status !== DoctorCheck::OK) {
                $output->writeln(str_repeat(' ', 25) . '-> ' . $check->hint);
            }
        }
        $output->writeln('');
        $output->writeln(sprintf('%d ok, %d warning(s), %d failure(s), %d skipped.',
            $counts[DoctorCheck::OK], $counts[DoctorCheck::WARN], $counts[DoctorCheck::FAIL], $counts[DoctorCheck::SKIP]));

        return $failed ? Command::FAILURE : Command::SUCCESS;
    }
}
