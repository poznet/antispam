<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use Doctrine\ORM\EntityManagerInterface;

/**
 * One scan pass of a mailbox account (IMAP pipeline or SSH agent), shared by
 * the scheduled `antispam:agent:scan-all` and the panel's background scan job
 * (Jobs\Handler\AccountScanHandler), so both use the same lock and the same
 * "when is a mailbox scanned" rules.
 *
 * IMAP passes can be limited (messages / deadline): the cursor is stored after
 * every pass, the next pass continues above it. While the *first* scan of a
 * mailbox is unfinished the account is not marked as scanned, so every pass of
 * that initial clean-up keeps running as "initial" (kept out of the stats) -
 * the cursor alone carries the progress.
 *
 * The SSH agent scans the Maildir in one command; it marks every message in
 * its own database as it goes, so a scan cut short by the timeout continues
 * on the next run, and its own lock refuses a second scan.
 */
class AccountScanner
{
    public function __construct(
        private EntityManagerInterface $em,
        private SshService $ssh,
        private ImapScanService $imapScan,
    ) {
    }

    /**
     * @return array scan counters + 'remaining' (IMAP messages left for the next
     *               pass), 'initial' (first scan, not finished yet when remaining > 0)
     *
     * @throws ScanLockedException the mailbox is being scanned by another process
     * @throws \RuntimeException   connection / agent failure
     */
    public function scan(Account $account, ?int $maxMessages = null, ?float $deadline = null): array
    {
        if ($account->isSsh()) {
            $result = $this->ssh->runScan($account);
            // An error answer (timeout, old agent, lock) is not a scan.
            if (!isset($result['total'])) {
                if (!empty($result['locked'])) {
                    throw new ScanLockedException('Agent na serwerze właśnie skanuje tę skrzynkę.');
                }
                throw new \RuntimeException(mb_substr((string)($result['error'] ?? 'nieprawidłowa odpowiedź agenta'), 0, 500));
            }
            if (!empty($result['agent_warning'])) {
                $result['errors'][] = $result['agent_warning'];
            }
            $result['remaining'] = 0;
            $result['initial'] = $account->getLastScanAt() === null;
        } else {
            $result = $this->imapScan->scanAccount($account, $maxMessages, $deadline);
        }

        return $result;
    }

    /**
     * One batch of a full rescan of the whole INBOX against the current rules
     * (markers ignored, spam moved - never deleted, kept out of the stats; see
     * ImapScanService::rescanAccount() and the agent's `rescan`).
     *
     * IMAP: $cursor is the 'cursor' of the previous batch (null = start); the
     * account's own scan cursor is not touched. SSH: the agent keeps the
     * progress itself, $first starts a new rescan there (--reset); the batch
     * length comes from $deadline.
     *
     * @return array counters + 'remaining' (0 = done) + 'cursor' (IMAP, for the next batch)
     *
     * @throws ScanLockedException the mailbox is being scanned by another process
     * @throws \RuntimeException   connection / agent failure (old agent: "wdróż go ponownie")
     */
    public function rescan(Account $account, ?array $cursor, bool $first, ?float $deadline = null): array
    {
        if (!$account->isSsh()) {
            return $this->imapScan->rescanAccount($account, $cursor, null, $deadline);
        }
        $seconds = $deadline !== null ? (int)ceil($deadline - microtime(true)) : 300;
        $result = $this->ssh->runRescan($account, $first, max(10, $seconds));
        if (!isset($result['total']) || empty($result['rescan'])) {
            if (!empty($result['locked'])) {
                throw new ScanLockedException('Agent na serwerze właśnie skanuje tę skrzynkę.');
            }
            throw new \RuntimeException(mb_substr((string)($result['error'] ?? 'nieprawidłowa odpowiedź agenta - wdróż go ponownie (Konta → Wdróż)'), 0, 500));
        }
        $result['errors'] = array_values((array)($result['errors'] ?? []));
        if (!empty($result['agent_warning'])) {
            $result['errors'][] = $result['agent_warning'];
        }
        unset($result['decisions'], $result['decisions_truncated'], $result['agent_warning'], $result['agent_outdated'], $result['warnings']);
        $result['remaining'] = (int)($result['remaining'] ?? 0);
        $result['cursor'] = null;
        return $result;
    }

    /**
     * Stores the end of a rescan on the account (list column), never the
     * dashboard's last scan. $complete: the whole INBOX was checked - the
     * stored progress is dropped; otherwise (failed) it stays, so the next
     * rescan continues from it.
     */
    public function finishRescan(Account $account, array $result, bool $complete = false): void
    {
        unset($result['cursor'], $result['initial'], $result['timing']);
        $account->markRescanned($result);
        if ($complete) {
            $this->saveRescanProgress($account, null);
        }
        $this->em->flush();
    }

    /**
     * Progress of an unfinished rescan (Account::$rescanProgress), saved after
     * every batch. Plain SQL as well: after an EntityManager reset the account
     * is detached and a flush alone would be lost.
     */
    public function saveRescanProgress(Account $account, ?array $progress): void
    {
        $account->setRescanProgress($progress);
        if ($account->getId() === null) {
            return;
        }
        $this->em->getConnection()->update('antispam_account', [
            'rescan_progress' => $progress === null ? null : json_encode($progress, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE),
        ], ['id' => $account->getId()]);
    }

    /**
     * Stores the result on the account (last scan time + counters) unless the
     * initial scan still has messages left.
     *
     * @param array $result the (possibly accumulated) counters to show on the account list
     *
     * @return bool true when the account was marked as scanned
     */
    public function finish(Account $account, array $result): bool
    {
        if (!empty($result['initial']) && (int)($result['remaining'] ?? 0) > 0) {
            return false;
        }
        unset($result['initial']);
        $account->markScanned($result);
        $this->em->flush();
        return true;
    }

    /**
     * Adds one pass to the counters of the previous passes of the same scan
     * (a background scan in several batches): counters are summed, 'total'
     * and 'remaining' are the latest, errors are capped at 20.
     */
    public static function accumulate(?array $sum, array $pass): array
    {
        if ($sum === null) {
            $pass['errors'] = array_slice(array_values((array)($pass['errors'] ?? [])), 0, 20);
            return $pass;
        }
        foreach (['checked', 'skipped', 'whitelisted', 'blacklisted', 'quarantined', 'moved_to_spam', 'move_failed'] as $k) {
            if ($k === 'move_failed' && !array_key_exists($k, $sum) && !array_key_exists($k, $pass)) {
                // SSH agents only
                continue;
            }
            $sum[$k] = (int)($sum[$k] ?? 0) + (int)($pass[$k] ?? 0);
        }
        foreach (['total', 'remaining', 'initial'] as $k) {
            if (array_key_exists($k, $pass)) {
                $sum[$k] = $pass[$k];
            }
        }
        $sum['errors'] = array_slice(array_merge((array)($sum['errors'] ?? []), (array)($pass['errors'] ?? [])), 0, 20);
        return $sum;
    }
}
