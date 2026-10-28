<?php

namespace AntispamBundle\Tests\Command;

use AntispamBundle\Command\CronRunCommand;
use AntispamBundle\Entity\CronRun;
use AntispamBundle\Repository\CronRunRepository;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Tester\CommandTester;

class CronRunCommandTest extends TestCase
{
    private function tester(?CronRun &$run = null): CommandTester
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('persist')->willReturnCallback(function ($e) use (&$run) { $run = $e; });
        $em->method('isOpen')->willReturn(true);
        $em->method('getRepository')->willReturn($this->createMock(CronRunRepository::class));

        $inner = new class('antispam:test:job') extends Command {
            protected function configure(): void
            {
                $this->addOption('scheduled-only', null, InputOption::VALUE_NONE);
            }

            protected function execute(InputInterface $input, OutputInterface $output): int
            {
                $output->writeln('scheduled-only=' . ($input->getOption('scheduled-only') ? 'yes' : 'no'));
                return 0;
            }
        };
        $app = new Application();
        $app->add($inner);
        $app->add(new CronRunCommand($em));

        return new CommandTester($app->find('antispam:cron:run'));
    }

    public function testRunsTheCommandWithoutArguments()
    {
        $tester = $this->tester($run);
        $tester->execute(['cmd' => 'antispam:test:job']);
        $this->assertStringContainsString('scheduled-only=no', $tester->getDisplay());
        $this->assertSame('antispam:test:job', $run->getCommand());
    }

    public function testPassesArgumentsAfterTheDoubleDash()
    {
        $tester = $this->tester($run);
        $tester->execute(['cmd' => 'antispam:test:job', 'args' => ['--scheduled-only']]);
        $this->assertStringContainsString('scheduled-only=yes', $tester->getDisplay());
        $this->assertSame('antispam:test:job --scheduled-only', $run->getCommand());
    }
}
