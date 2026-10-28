<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Pushes rules and settings to an SSH agent: "Synchronizuj" in the panel and
 * rule changes in the user area (DeferredAgentSync, payload background=true).
 * Not exclusive: a change made while a sync runs queues another one, since
 * the running sync may have exported the rules before the change.
 */
class AccountSyncHandler implements JobHandlerInterface
{
    use AccountJobTrait;

    public function __construct(
        private EntityManagerInterface $em,
        private SshService $ssh,
        private AgentRulesExporter $rulesExporter,
    ) {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_ACCOUNT_SYNC;
    }

    public static function exclusive(): bool
    {
        return false;
    }

    public function handle(JobContext $context): array
    {
        $account = $this->account($this->em, $context, true);
        $background = !empty($context->payload()['background']);
        $result = ['success' => false, 'messages' => []];

        try {
            $context->progress('Wysyłanie reguł do agenta...');
            $syncResult = $this->ssh->syncRules($account, json_encode($this->rulesExporter->export($account->getEmail(), $account)));
            $result['sync_result'] = $syncResult;
            if (($syncResult['success'] ?? null) === true) {
                $result['success'] = true;
                $result['messages'][] = 'Reguły zostały zsynchronizowane';
            } else {
                $result['messages'][] = 'Synchronizacja nie powiodła się: ' . ($syncResult['error'] ?? 'nieznany błąd');
            }
            if (!empty($syncResult['agent_warning'])) {
                $result['messages'][] = $syncResult['agent_warning'];
            }
        } catch (\Exception $e) {
            $result['messages'][] = 'Synchronizacja nie powiodła się: ' . $e->getMessage();
        }

        if ($background) {
            // User-area rule change: nobody watches the job page, so a failure
            // must show up as a failed job (queue list, health check).
            if (!$result['success']) {
                throw new \RuntimeException(implode(' ', $result['messages']));
            }
        } else {
            $context->audit('account.sync', targetType: 'account', targetId: $account->getId(), label: $account->getName(), mailbox: $account->getEmail(), details: ['ok' => $result['success']]);
        }

        return $result;
    }
}
