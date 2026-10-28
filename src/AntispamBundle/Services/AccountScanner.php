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
        foreach (['checked', 'skipped', 'whitelisted', 'blacklisted', 'quarantined', 'moved_to_spam'] as $k) {
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
