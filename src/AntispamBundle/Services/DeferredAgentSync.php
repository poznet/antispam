<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Pushes the rules of SSH+Maildir accounts to their agents after the response
 * has been sent - an SSH login plus an SFTP upload takes seconds, so a rule
 * change in the user area (/my/rules, "Zawsze akceptuj" in /my/spam) is not
 * kept waiting for it. Same early-close handling as DeferredRetroactivePass
 * (Content-Length + Connection: close under mod_php).
 *
 * Only accounts with a deployed agent are synced; IMAP accounts read the
 * rules from the database on every scan and need nothing.
 */
class DeferredAgentSync implements EventSubscriberInterface, ResetInterface
{
    /** @var array<int, true> Account ids */
    private array $pending = [];

    public function __construct(
        private EntityManagerInterface $em,
        private SshService $ssh,
        private AgentRulesExporter $exporter,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => ['onResponse', -1024],
            KernelEvents::TERMINATE => 'onTerminate',
        ];
    }

    /** @return bool true when the account will be synced */
    public function defer(Account $account): bool
    {
        if (!$account->isSsh() || !$account->getAgentDeployed() || $account->getId() === null) {
            return false;
        }
        $this->pending[(int)$account->getId()] = true;
        return true;
    }

    /**
     * Schedule every SSH account whose mailbox address is $owner.
     *
     * @return int number of accounts scheduled
     */
    public function deferForOwner(string $owner): int
    {
        if ($owner === '' || RuleOwnership::isGlobal($owner)) {
            return 0;
        }
        $n = 0;
        foreach ($this->em->getRepository(Account::class)->findBy(['email' => $owner, 'connectionType' => Account::CONNECTION_SSH]) as $account) {
            $n += $this->defer($account) ? 1 : 0;
        }
        return $n;
    }

    public function hasPending(): bool
    {
        return $this->pending !== [];
    }

    public function onResponse(ResponseEvent $event): void
    {
        if ($this->pending && $event->isMainRequest()) {
            DeferredRetroactivePass::prepareEarlyClose($event->getResponse());
        }
    }

    public function onTerminate(TerminateEvent $event): void
    {
        $this->runPending();
    }

    /** @return int number of accounts synced successfully */
    public function runPending(): int
    {
        if (!$this->pending) {
            return 0;
        }
        $ids = array_keys($this->pending);
        $this->pending = [];

        ignore_user_abort(true);
        @set_time_limit(0);

        $ok = 0;
        foreach ($ids as $id) {
            try {
                if (!$this->em->isOpen()) {
                    break;
                }
                $account = $this->em->find(Account::class, $id);
                if (!$account || !$account->isSsh()) {
                    continue;
                }
                $result = $this->ssh->syncRules($account, json_encode($this->exporter->export($account->getEmail())));
                if (($result['success'] ?? null) === true) {
                    $ok++;
                    $this->logger?->info('antispam: agent rules synced after a user rule change', ['account' => $id]);
                } else {
                    $this->logger?->warning('antispam: deferred agent rules sync failed', ['account' => $id, 'error' => $result['error'] ?? null]);
                }
            } catch (\Throwable $e) {
                $this->logger?->error('antispam: deferred agent rules sync failed', ['account' => $id, 'exception' => $e]);
            }
        }
        return $ok;
    }

    public function reset(): void
    {
        $this->pending = [];
    }
}
