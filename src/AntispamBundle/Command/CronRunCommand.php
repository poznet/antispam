<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\CronRun;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArgvInput;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs another antispam:* command and records it in the cron log
 * (Przegląd → Logi crona): start/end time, exit code and output. The output
 * is still printed, so `docker logs` keeps working.
 *
 *   php bin/console antispam:cron:run antispam:agent:scan-all
 *   php bin/console antispam:cron:run antispam:digest:send -- --scheduled-only
 *
 * Arguments / options for the wrapped command follow after `--`.
 */
#[AsCommand(name: 'antispam:cron:run', description: 'Run an antispam:* command and store its output in the cron log')]
class CronRunCommand extends Command
{
    public function __construct(private EntityManagerInterface $em)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addArgument('cmd', InputArgument::REQUIRED, 'Command to run, e.g. antispam:agent:scan-all')
             ->addArgument('args', InputArgument::IS_ARRAY | InputArgument::OPTIONAL, 'Arguments / options of that command, after "--" (e.g. -- --scheduled-only)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $name = (string)$input->getArgument('cmd');
        if (!str_starts_with($name, 'antispam:') || $name === $this->getName()) {
            $output->writeln('<error>Only antispam:* commands can be logged</error>');
            return Command::INVALID;
        }
        $command = $this->getApplication()->find($name);

        $args = array_values(array_map('strval', (array)$input->getArgument('args')));
        $label = $args ? $name . ' ' . implode(' ', $args) : $name;

        $run = new CronRun($label);
        $this->em->persist($run);
        $this->em->flush();

        $buffer = new BufferedOutput(OutputInterface::VERBOSITY_NORMAL, false);
        try {
            $code = $command->run($args ? new ArgvInput(array_merge(['console', $name], $args)) : new ArrayInput([]), $buffer);
        } catch (\Throwable $e) {
            $buffer->writeln('EXCEPTION: ' . get_class($e) . ': ' . $e->getMessage());
            $code = Command::FAILURE;
        }
        $text = $buffer->fetch();
        $output->write($text, false, OutputInterface::OUTPUT_RAW);

        // The wrapped command may have cleared/closed the EntityManager.
        if (!$this->em->isOpen()) {
            $output->writeln('<comment>EntityManager closed - cron log entry left unfinished</comment>');
            return $code;
        }
        $run = $this->em->find(CronRun::class, $run->getId()) ?? $run;
        $run->finish($code, $text);
        $this->em->flush();
        $this->em->getRepository(CronRun::class)->purgeOlderThan(new \DateTime('-' . CronRun::RETENTION_DAYS . ' days'));

        return $code;
    }
}
