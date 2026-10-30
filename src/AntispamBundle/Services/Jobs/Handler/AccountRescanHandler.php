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

    /** Seconds before retrying a failed batch; the job fails after the last one. */
    const RETRY_DELAYS = [60, 120, 300, 600, 900];

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
        if (!$state) {
            $state = $this->resumeState($account, !empty($context->payload()['restart']));
        }
        $sum = $state['result'] ?? null;
        $done = $sum ? (int)$sum['checked'] : 0;

        if ($account->isSsh() && !$account->getAgentDeployed()) {
            $this->fail($context, $account, $sum, $trigger, 'Agent nie jest wdrożony na serwerze - najpierw użyj przycisku Wdróż.');
        }
        if (!empty($state['resumed_from']) && empty($state['resume_noted'])) {
            $state['resume_noted'] = true;
            $context->progress(sprintf('Wznowiono przerwany ponowny skan (%s) - sprawdzono już %d', $state['resumed_from'], $done), $done, $done + (int)($sum['remaining'] ?? 0));
        } elseif ($sum) {
            $context->progress(sprintf('Ponowny skan - kolejna partia (sprawdzono %d)', $done), $done, $done + (int)($sum['remaining'] ?? 0));
        } else {
            $context->progress($account->isSsh() ? 'Agent sprawdza ponownie cały Maildir...' : 'Łączenie ze skrzynką IMAP, ponowny skan całej skrzynki...');
        }

        try {
            $pass = $this->scanner->rescan($account, $state['cursor'] ?? null, empty($state['started']), $context->batchDeadline());
        } catch (ScanLockedException $e) {
            $waits = (int)($state['lock_waits'] ?? 0) + 1;
            if ($waits > AccountScanHandler::MAX_LOCK_WAITS) {
                $this->fail($context, $account, $sum, $trigger, 'Skrzynka jest od ponad godziny skanowana przez inny proces - spróbuj później.');
            }
            $context->continueLater(['lock_waits' => $waits] + $state, AccountScanHandler::LOCK_RETRY_SECONDS,
                'Czeka: skrzynkę skanuje teraz inny proces - ponowna próba za ' . AccountScanHandler::LOCK_RETRY_SECONDS . ' s');
            return [];
        } catch (\Throwable $e) {
            // Connection drop, IMAP timeout, STATUS failure: the same batch again
            // later, from the same cursor - fail only after RETRY_DELAYS run out.
            $retries = (int)($state['retries'] ?? 0);
            // An agent that does not know the command waits for a redeploy, not for time.
            $permanent = str_contains($e->getMessage(), 'wdróż go ponownie');
            if (!$permanent && $retries < count(self::RETRY_DELAYS)) {
                $delay = self::RETRY_DELAYS[$retries];
                $context->continueLater(['retries' => $retries + 1, 'last_error' => mb_substr($e->getMessage(), 0, 300)] + $state, $delay,
                    sprintf('Błąd przebiegu (%s) - ponowna próba %d/%d za %d s, postęp zachowany (sprawdzono %d)', mb_substr($e->getMessage(), 0, 120), $retries + 1, count(self::RETRY_DELAYS), $delay, $done));
                return [];
            }
            $this->fail($context, $account, $sum, $trigger, $e->getMessage());
        }

        $cursor = $pass['cursor'] ?? null;
        unset($pass['cursor'], $pass['timing']);
        $sum = AccountScanner::accumulate($sum, $pass);
        $done = (int)$sum['checked'];
        $remaining = (int)($sum['remaining'] ?? 0);
        if ($remaining > 0) {
            // On the account too: a failed / cancelled / killed job does not lose it.
            $this->scanner->saveRescanProgress($account, ['cursor' => $cursor, 'result' => $sum, 'job' => $context->jobId(), 'at' => (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM)]);
            $context->progress(sprintf('Sprawdzono ponownie %d wiadomości, zostało %d', $done, $remaining), $done, $done + $remaining);
            $context->continueLater(['result' => $sum, 'cursor' => $cursor, 'started' => true, 'lock_waits' => 0, 'retries' => 0] + $state, 0);
            return [];
        }

        $sum['rescan'] = true;
        $sum['trigger'] = $trigger;
        $this->scanner->finishRescan($account, $sum + ['job' => $context->jobId()], true);
        $this->audit($context, $account, $sum, $trigger, null);
        $context->progress('Zakończone', $done, $done);
        return ['success' => true, 'messages' => [], 'scan_result' => $sum];
    }

    /**
     * State of a new job: continue the account's unfinished rescan (failed,
     * cancelled or killed earlier) unless $restart. The counters of the
     * earlier part are carried on, so the result covers the whole INBOX. SSH:
     * 'started' keeps --reset off, the agent continues its own progress.
     */
    private function resumeState(Account $account, bool $restart): array
    {
        $progress = $account->getRescanProgress();
        if ($restart || !$progress) {
            if ($progress) {
                $this->scanner->saveRescanProgress($account, null);
            }
            return [];
        }
        $at = isset($progress['at']) ? date('Y-m-d H:i', strtotime((string)$progress['at']) ?: time()) : '?';
        return [
            'cursor' => $progress['cursor'] ?? null,
            'result' => $progress['result'] ?? null,
            'started' => true,
            'resumed_from' => 'zadanie #' . ($progress['job'] ?? '?') . ', ' . $at,
        ];
    }

    /** Ends the job as failed; the account's rescan progress stays for the next rescan. */
    private function fail(JobContext $context, Account $account, ?array $sum, string $trigger, string $error): never
    {
        // Remember the failure on the account too (list column, weekly schedule);
        // never let that bookkeeping hide the real error (e.g. a closed EntityManager).
        try {
            $this->scanner->finishRescan($account, ['error' => mb_substr($error, 0, 500), 'trigger' => $trigger, 'job' => $context->jobId()] + ($sum ?? []));
        } catch (\Throwable) {
        }
        $this->audit($context, $account, $sum, $trigger, $error);
        throw new \RuntimeException($error);
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
