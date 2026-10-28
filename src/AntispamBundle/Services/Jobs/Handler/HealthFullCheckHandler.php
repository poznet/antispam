<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\HealthService;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;

/** "Pełne sprawdzenie" on Stan systemu: logs in to every IMAP account and queries every SSH agent. */
class HealthFullCheckHandler implements JobHandlerInterface
{
    public function __construct(private HealthService $health)
    {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_HEALTH_FULL;
    }

    public static function exclusive(): bool
    {
        return true;
    }

    public function handle(JobContext $context): array
    {
        $context->progress('Logowanie do skrzynek i odpytywanie agentów...');
        return $this->health->run(true);
    }
}
