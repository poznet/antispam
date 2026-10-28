<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AccountScanner;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\ScanLockedException;
use Doctrine\ORM\EntityManagerInterface;

/**
 * "Przeskanuj całą skrzynkę ponownie" and the weekly rescan
 * (antispam:rescan:due): the whole INBOX of one account is checked again
 * against the current rules, in batches of the worker's batch length. The
 * job re-queues itself until INBOX is done; the IMAP progress lives in the
 * job state (its own cursor - the account's scan cursor is untouched), the
 * SSH agent keeps its own (rescan_done table).
 *
 * Kept out of the statistics (score log `initial_scan`, source `rescan`);
 * spam is moved, never deleted. The end (counters or error) is stored on the
 * account (lastRescanAt / lastRescanResult) and audited as `account.rescan`.
 *
 * While the scheduled scan holds the mailbox lock the job waits like a scan.
 */
class AccountRescanHandler implements JobHandlerInterface
{
    use AccountJobTrait;

    public function __construct(
        private EntityManagerInterface $em,
        private AccountScanner $scanner,
    ) {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_ACCOUNT_RESCAN;
    }

    public static function exclusive(): bool
    {
        return true;
    }

    public function handle(JobContext $context): array
    {
        $account = $this->account($this->em, $context);
        $trigger = (string)($context->payload()['trigger'] ?? 'panel');
        $state = $context->state();
        $sum = $state['result'] ?? null;
        $done = $sum ? (int)$sum['checked'] : 0;

        try {
            if ($account->isSsh() && !$account->getAgentDeployed()) {
                throw new \RuntimeException('Agent nie jest wdrożony na serwerze - najpierw użyj przycisku Wdróż.');
            }
            if ($sum) {
                $context->progress(sprintf('Ponowny skan - kolejna partia (sprawdzono %d)', $done), $done, $done + (int)($sum['remaining'] ?? 0));
            } else {
                $context->progress($account->isSsh() ? 'Agent sprawdza ponownie cały Maildir...' : 'Łączenie ze skrzynką IMAP, ponowny skan całej skrzynki...');
            }

            try {
                $pass = $this->scanner->rescan($account, $state['cursor'] ?? null, empty($state['started']), $context->batchDeadline());
            } catch (ScanLockedException $e) {
                $waits = (int)($state['lock_waits'] ?? 0) + 1;
                if ($waits > AccountScanHandler::MAX_LOCK_WAITS) {
                    throw new \RuntimeException('Skrzynka jest od ponad godziny skanowana przez inny proces - spróbuj później.');
                }
                $context->continueLater(['lock_waits' => $waits] + $state, AccountScanHandler::LOCK_RETRY_SECONDS,
                    'Czeka: skrzynkę skanuje teraz inny proces - ponowna próba za ' . AccountScanHandler::LOCK_RETRY_SECONDS . ' s');
                return [];
            }
        } catch (\Throwable $e) {
            // Remember the failure on the account too (list column, weekly schedule);
            // never let that bookkeeping hide the real error (e.g. a closed EntityManager).
            try {
                $this->scanner->finishRescan($account, ['error' => mb_substr($e->getMessage(), 0, 500), 'trigger' => $trigger, 'job' => $context->jobId()] + ($sum ?? []));
            } catch (\Throwable) {
            }
            $this->audit($context, $account, $sum, $trigger, $e->getMessage());
            throw $e;
        }

        $cursor = $pass['cursor'] ?? null;
        unset($pass['cursor']);
        $sum = AccountScanner::accumulate($sum, $pass);
        $done = (int)$sum['checked'];
        $remaining = (int)($sum['remaining'] ?? 0);
        if ($remaining > 0) {
            $context->progress(sprintf('Sprawdzono ponownie %d wiadomości, zostało %d', $done, $remaining), $done, $done + $remaining);
            $context->continueLater(['result' => $sum, 'cursor' => $cursor, 'started' => true, 'lock_waits' => 0], 0);
            return [];
        }

        $sum['rescan'] = true;
        $sum['trigger'] = $trigger;
        $this->scanner->finishRescan($account, $sum + ['job' => $context->jobId()]);
        $this->audit($context, $account, $sum, $trigger, null);
        $context->progress('Zakończone', $done, $done);
        return ['success' => true, 'messages' => [], 'scan_result' => $sum];
    }

    private function audit(JobContext $context, Account $account, ?array $sum, string $trigger, ?string $error): void
    {
        $details = ['ok' => $error === null, 'trigger' => $trigger];
        foreach (['total', 'checked', 'whitelisted', 'blacklisted', 'quarantined', 'moved_to_spam'] as $k) {
            $details[$k] = (int)($sum[$k] ?? 0);
        }
        if ($error !== null) {
            $details['error'] = mb_substr($error, 0, 300);
        }
        $context->audit('account.rescan', targetType: 'account', targetId: $account->getId(), label: $account->getName(), mailbox: $account->getEmail(), details: $details);
    }
}
