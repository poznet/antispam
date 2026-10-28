<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;

/** "Wdróż" (SSH accounts): upload + test the agent, then push rules and settings. */
class AccountDeployHandler implements JobHandlerInterface
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
        return BackgroundJob::TYPE_ACCOUNT_DEPLOY;
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
            $context->progress('Wysyłanie i test agenta na serwerze...');
            $deployResult = $this->ssh->deployAgent($account);
            $result['deploy_result'] = $deployResult;
            if (($deployResult['success'] ?? null) === true) {
                $account->setAgentDeployed(true);
                $this->em->flush();
                $result['success'] = true;
                $result['messages'][] = 'Agent został wdrożony (' . ($deployResult['remote_path'] ?? '') . ', wersja ' . ($deployResult['agent_version'] ?? '?') . ')';
                // Settings (thresholds, switches) and rules live in the agent's
                // per-account database: push them right away.
                $context->progress('Synchronizacja reguł i ustawień...');
                $sync = $this->ssh->syncRules($account, json_encode($this->rulesExporter->export($account->getEmail(), $account)));
                $result['messages'][] = ($sync['success'] ?? false) === true
                    ? 'Reguły i ustawienia zostały zsynchronizowane'
                    : 'Synchronizacja reguł nie powiodła się: ' . ($sync['error'] ?? 'nieznany błąd') . ' - użyj przycisku Synchronizuj.';
            } else {
                $result['messages'][] = 'Wdrożenie nie powiodło się: ' . ($deployResult['error'] ?? 'test agenta nie przeszedł');
            }
        } catch (\Exception $e) {
            $result['messages'][] = 'Wdrożenie nie powiodło się: ' . $e->getMessage();
        }
        $context->audit('account.deploy', targetType: 'account', targetId: $account->getId(), label: $account->getName(), mailbox: $account->getEmail(), details: ['ok' => $result['success']]);

        return $result;
    }
}
