<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;

/** "Stan" (SSH accounts): the agent's health report. */
class AgentHealthHandler implements JobHandlerInterface
{
    use AccountJobTrait;

    public function __construct(
        private EntityManagerInterface $em,
        private SshService $ssh,
    ) {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_ACCOUNT_HEALTH;
    }

    public static function exclusive(): bool
    {
        return true;
    }

    public function handle(JobContext $context): array
    {
        $account = $this->account($this->em, $context, true);
        $result = ['success' => false, 'messages' => []];
        try {
            $context->progress('Odpytywanie agenta...');
            $health = $this->ssh->runHealth($account);
            $result['success'] = !isset($health['success']) || $health['success'] !== false;
            $result['health'] = $health;
            foreach (['error', 'agent_warning'] as $k) {
                if (!empty($health[$k])) {
                    $result['messages'][] = $health[$k];
                }
            }
        } catch (\Exception $e) {
            $result['messages'][] = 'Sprawdzenie stanu agenta nie powiodło się: ' . $e->getMessage();
        }
        return $result;
    }
}
