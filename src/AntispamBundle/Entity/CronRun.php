<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\CronRunRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * One run of a periodic console command started through `antispam:cron:run`
 * (the Docker scheduler or a host crontab): what ran, how it ended and its
 * output. Shown on Przegląd → Logi crona, kept for RETENTION_DAYS.
 */
#[ORM\Entity(repositoryClass: CronRunRepository::class)]
#[ORM\Table(name: 'antispam_cron_run')]
#[ORM\Index(name: 'idx_cron_started_at', columns: ['started_at'])]
class CronRun
{
    const RETENTION_DAYS = 14;
    const MAX_OUTPUT = 60000;

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'command', type: 'string', length: 100)]
    private $command;

    #[ORM\Column(name: 'started_at', type: 'datetime')]
    private $startedAt;

    #[ORM\Column(name: 'finished_at', type: 'datetime', nullable: true)]
    private $finishedAt;

    /** null while running (or when the process died) */
    #[ORM\Column(name: 'exit_code', type: 'integer', nullable: true)]
    private $exitCode;

    #[ORM\Column(name: 'output', type: 'text', nullable: true)]
    private $output;

    public function __construct($command)
    {
        $this->command = substr((string)$command, 0, 100);
        $this->startedAt = new \DateTime();
    }

    public function getId() { return $this->id; }
    public function getCommand() { return $this->command; }
    public function getStartedAt() { return $this->startedAt; }
    public function getFinishedAt() { return $this->finishedAt; }
    public function getExitCode() { return $this->exitCode; }
    public function getOutput() { return $this->output; }

    public function finish($exitCode, $output)
    {
        $output = (string)$output;
        if (strlen($output) > self::MAX_OUTPUT) {
            $output = substr($output, 0, self::MAX_OUTPUT) . "\n[... output truncated]";
        }
        $this->exitCode = (int)$exitCode;
        $this->output = mb_scrub($output, 'UTF-8');
        $this->finishedAt = new \DateTime();
        return $this;
    }

    /** Duration in seconds, null while running. */
    public function getDuration()
    {
        return $this->finishedAt ? $this->finishedAt->getTimestamp() - $this->startedAt->getTimestamp() : null;
    }

    public function isRunning() { return $this->finishedAt === null; }
    public function isSuccess() { return $this->exitCode === 0; }
}
