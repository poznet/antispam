<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AccountScanner;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\ScanLockedException;
use Doctrine\ORM\EntityManagerInterface;

/**
 * "Skanuj" on the account list. IMAP: one batch per run (JobWorker batch
 * length), the cursor is stored after each batch and the job re-queues itself
 * until INBOX is done, so a first scan of a huge mailbox shows progress and
 * never hits the job time limit. SSH: one agent scan.
 *
 * While the scheduled scan (or the agent) holds the mailbox lock, the job
 * waits in the queue and tries again every LOCK_RETRY_SECONDS.
 */
class AccountScanHandler implements JobHandlerInterface
{
    use AccountJobTrait;

    const LOCK_RETRY_SECONDS = 30;
    /** 120 x 30 s: give up after an hour of waiting. */
    const MAX_LOCK_WAITS = 120;

    public function __construct(
        private EntityManagerInterface $em,
        private AccountScanner $scanner,
    ) {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_ACCOUNT_SCAN;
    }

    public static function exclusive(): bool
    {
        return true;
    }

    public function handle(JobContext $context): array
    {
        $account = $this->account($this->em, $context);
        if ($account->isSsh() && !$account->getAgentDeployed()) {
            throw new \RuntimeException('Agent nie jest wdrożony na serwerze - najpierw użyj przycisku Wdróż.');
        }
        $state = $context->state();
        $sum = $state['result'] ?? null;
        $done = $sum ? (int)$sum['checked'] + (int)$sum['skipped'] : 0;

        if ($sum) {
            $context->progress(sprintf('Skanowanie - kolejna partia (przetworzono %d)', $done), $done, $done + (int)($sum['remaining'] ?? 0));
        } else {
            $context->progress($account->isSsh() ? 'Agent skanuje Maildir na serwerze...' : 'Łączenie ze skrzynką IMAP i skanowanie...');
        }

        try {
            $pass = $this->scanner->scan($account, null, $context->batchDeadline());
        } catch (ScanLockedException $e) {
            $waits = (int)($state['lock_waits'] ?? 0) + 1;
            if ($waits > self::MAX_LOCK_WAITS) {
                throw new \RuntimeException('Skrzynka jest od ponad godziny skanowana przez inny proces - spróbuj później.');
            }
            $context->continueLater(['result' => $sum, 'lock_waits' => $waits], self::LOCK_RETRY_SECONDS,
                'Czeka: skrzynkę skanuje teraz inny proces (harmonogram) - ponowna próba za ' . self::LOCK_RETRY_SECONDS . ' s');
            return [];
        }

        $sum = AccountScanner::accumulate($sum, $pass);
        $done = (int)$sum['checked'] + (int)$sum['skipped'];
        $remaining = (int)($sum['remaining'] ?? 0);
        if ($remaining > 0) {
            $context->progress(sprintf('Przetworzono %d wiadomości, zostało %d', $done, $remaining), $done, $done + $remaining);
            $context->continueLater(['result' => $sum, 'lock_waits' => 0], 0);
            return [];
        }

        $this->scanner->finish($account, $sum);
        $context->progress('Zakończone', $done, $done);
        return ['success' => true, 'messages' => [], 'scan_result' => $sum];
    }
}
