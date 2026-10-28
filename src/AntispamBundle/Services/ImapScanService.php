<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Imap\ImapClient;
use AntispamBundle\Imap\ImapException;
use AntispamBundle\Imap\SocketConnection;
use AntispamBundle\Services\OAuth\OAuthSettings;
use AntispamBundle\Services\OAuth\OAuthTokenManager;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\Exception\InvalidSearchCriteriaException;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\Search\Date\Since;
use Ddeboer\Imap\Server;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Runs the INBOX of an IMAP mailbox through the `antispam.check.message`
 * pipeline: spam goes to SPAM (or is deleted), suspicious mail to QUARANTINE.
 * Used for both IMAP accounts (Konta) and the legacy mailbox from the
 * "E-mail" settings, by the panel and by `antispam:agent:scan-all`.
 *
 * INBOX is read incrementally: every mailbox keeps a cursor (UIDVALIDITY +
 * highest UID already processed) and a scan only fetches UIDs above it. How a
 * scan picks its messages:
 *   - cursor valid            -> UIDs above the cursor (normal case, cheap)
 *   - first scan of a mailbox -> whole INBOX (initial clean-up, as before)
 *   - cursor 0/0              -> whole INBOX ("reset checked flags" button)
 *   - no cursor, but scanned before (upgrade), or UIDVALIDITY changed
 *                             -> only mail that arrived since the last scan
 *                                (minus a day); older mail is never touched
 * Markers (MessageService) still guard against double processing above the
 * cursor. One scan per mailbox at a time (file lock in var/data/locks, a busy
 * lock throws ScanLockedException).
 *
 * A scan can be limited (`$maxMessages` / `$deadline`, used by background
 * jobs and scan-all): a whole-INBOX or incremental pass then stops after the
 * limit and stores the cursor at the last processed UID, so the next call
 * continues where this one stopped ('remaining' in the result). A big first
 * scan therefore never has to fit into one job / cron time limit.
 */
class ImapScanService
{
    /** c-client timeouts (seconds) for every IMAP connection of the app. */
    const IMAP_OPEN_TIMEOUT = 20;
    const IMAP_READ_TIMEOUT = 60;

    /** Config key of the legacy mailbox cursor ("uidvalidity:last_uid:unix time"). */
    const LEGACY_CURSOR_KEY = 'imap.legacy_cursor';
    /** Look-back for a cursor-less pass when the time of the last scan is unknown. */
    const FALLBACK_WINDOW_DAYS = 3;

    const MODE_INCREMENTAL = 'incremental';
    const MODE_FULL = 'full';
    const MODE_SINCE = 'since';

    public function __construct(
        private EventDispatcherInterface $dispatcher,
        private ConnectionService $legacyConnection,
        private ConfigService $config,
        private CryptoService $crypto,
        private MessageService $messages,
        private ?ManagerRegistry $doctrine = null,
        #[Autowire('%kernel.project_dir%/var/data/locks')] private ?string $lockDir = null,
        private ?MailboxSettingsResolver $mailboxSettings = null,
        private ?OAuthTokenManager $oauthTokens = null,
    ) {
    }

    /**
     * Sets c-client open/read/write/close timeouts. They are process-wide, so
     * every code path that opens an IMAP connection must call this first
     * (ImapScanService::connect and ConnectionService do) - otherwise a
     * stalled server hangs the scan, and with it every later cron tick.
     */
    public static function applyImapTimeouts($open = self::IMAP_OPEN_TIMEOUT, $read = self::IMAP_READ_TIMEOUT)
    {
        if (!\function_exists('imap_timeout')) {
            return;
        }
        @imap_timeout(IMAP_OPENTIMEOUT, (int)$open);
        @imap_timeout(IMAP_READTIMEOUT, (int)$read);
        @imap_timeout(IMAP_WRITETIMEOUT, (int)$read);
        @imap_timeout(IMAP_CLOSETIMEOUT, (int)$open);
    }

    /**
     * Opens an IMAP connection for an IMAP account: ext-imap with the
     * password, or the socket client with SASL XOAUTH2 for OAuth accounts
     * (Microsoft 365 / Google, docs/oauth.md). Both return the same ddeboer
     * ConnectionInterface, so callers do not care which one they got.
     */
    public function connect(Account $account, ?int $openTimeout = null, ?int $readTimeout = null): ConnectionInterface
    {
        $openTimeout = $openTimeout ?? self::IMAP_OPEN_TIMEOUT;
        $readTimeout = $readTimeout ?? self::IMAP_READ_TIMEOUT;
        if ($account->isOAuth()) {
            return $this->connectOAuth($account, $openTimeout, $readTimeout);
        }
        self::applyImapTimeouts($openTimeout, $readTimeout);
        $server = new Server($account->getImapHost(), $account->getImapPort(), $account->getImapFlags());
        return $server->authenticate($account->getImapLogin(), (string)$this->crypto->decrypt($account->getImapPassword()));
    }

    private function connectOAuth(Account $account, int $openTimeout, int $readTimeout): ConnectionInterface
    {
        if ($this->oauthTokens === null) {
            throw new \RuntimeException('Logowanie OAuth nie jest dostępne w tym kontekście.');
        }
        [$host, $port, $encryption, $validate] = self::oauthEndpoint($account);
        $user = $account->getOAuthImapUser();

        $attempt = function () use ($account, $host, $port, $encryption, $validate, $user, $openTimeout, $readTimeout): SocketConnection {
            $client = new ImapClient($readTimeout, $openTimeout);
            $client->connect($host, $port, $encryption, $validate);
            try {
                $client->authenticateXoauth2($user, $this->oauthTokens->getAccessToken($account));
            } catch (\Throwable $e) {
                $client->disconnect();
                throw $e;
            }
            return new SocketConnection($client);
        };
        try {
            return $attempt();
        } catch (ImapException $e) {
            // A stored token can be refused before its expiry (revoked session,
            // changed password): get a new one once and retry.
            if (!str_contains($e->getMessage(), '(XOAUTH2) odrzucone')) {
                throw $e;
            }
            $this->oauthTokens->invalidate($account);
            return $attempt();
        }
    }

    /**
     * Host, port, encryption and certificate check of an OAuth account. A
     * token must never travel unencrypted: "no encryption" is refused and
     * "STARTTLS if available" becomes required STARTTLS.
     *
     * @return array{0:string, 1:int, 2:string, 3:bool}
     */
    public static function oauthEndpoint(Account $account): array
    {
        $host = trim((string)$account->getImapHost());
        if ($host === '') {
            $host = OAuthSettings::DEFAULT_IMAP_HOST[$account->getOAuthProvider() ?? OAuthSettings::MICROSOFT];
        }
        $options = ImapFlags::parse($account->getImapFlags());
        $encryption = match ($options['encryption']) {
            ImapFlags::ENCRYPTION_SSL => ImapClient::ENC_SSL,
            ImapFlags::ENCRYPTION_STARTTLS, ImapFlags::ENCRYPTION_AUTO => ImapClient::ENC_STARTTLS,
            default => throw new \RuntimeException('Logowanie OAuth wymaga szyfrowania (SSL/TLS lub STARTTLS) - token nie może być wysłany otwartym tekstem.'),
        };
        $port = (int)$account->getImapPort() ?: ($encryption === ImapClient::ENC_SSL ? 993 : 143);
        return [$host, $port, $encryption, (bool)$options['validate_cert']];
    }

    public function isLegacyConfigured(): bool
    {
        return $this->config->get('imap') && $this->config->get('login');
    }

    /**
     * @param int|null   $maxMessages at most this many messages in this call (null = all)
     * @param float|null $deadline    microtime(true) after which no further message is started
     *
     * @return array scan() counters + 'remaining' (messages left for the next call, 0 = done)
     *               and 'initial' (true while the first scan of the mailbox is in progress)
     *
     * @throws ScanLockedException another process is scanning this mailbox
     */
    public function scanAccount(Account $account, ?int $maxMessages = null, ?float $deadline = null): array
    {
        $lock = $this->lock(self::accountLockName($account));
        try {
            $connection = $this->connect($account);
            try {
                $since = $account->getLastScanAt() ? $this->windowStart($account->getLastScanAt()) : null;
                // The account's thresholds / scoring switch (override -> global)
                // apply to every listener of the pipeline while it runs.
                $settings = $this->mailboxSettings?->forAccount($account);
                $cursor = null;
                $run = function () use ($connection, $account, $settings, $since, &$cursor, $maxMessages, $deadline) {
                    return $this->scan($connection, $account->getEmail(), $settings ? $settings->deleteSpam : (bool)$account->getDeleteSpam(), $account->getLastScanAt() === null, $account->getImapCursor(), $since, $cursor, $maxMessages, $deadline);
                };
                $stats = $settings ? $this->mailboxSettings->within($settings, $run) : $run();
            } finally {
                $connection->close();
            }
            $this->saveAccountCursor($account, $cursor);
            $stats['initial'] = $account->getLastScanAt() === null;
            return $stats;
        } finally {
            $this->unlock($lock);
        }
    }

    /** Name of the per-mailbox scan lock (shared by the panel jobs and scan-all). */
    public static function accountLockName(Account $account): string
    {
        return 'account-' . strtolower((string)$account->getEmail()) . '-' . $account->getId();
    }

    /** The mailbox from the "E-mail" settings page (`antispam:go`). */
    public function scanLegacy(): array
    {
        $lock = $this->lock('legacy');
        try {
            $stored = self::decodeCursor($this->config->get(self::LEGACY_CURSOR_KEY));
            $scannedBefore = $stored !== null || $this->messages->hasAnyMarkers();
            $since = null;
            if ($scannedBefore) {
                $since = $this->windowStart(isset($stored['scanned_at']) ? (new \DateTimeImmutable())->setTimestamp($stored['scanned_at']) : null);
            }
            $stats = $this->scan($this->legacyConnection->getConnection(), (string)$this->config->get('email'), null, false, $stored, $since, $cursor);
            $this->config->set(self::LEGACY_CURSOR_KEY, self::encodeCursor($cursor));
            return $stats;
        } finally {
            $this->unlock($lock);
        }
    }

    /**
     * @param bool|null $deleteSpam null = global "delete" setting
     * @param bool $initialScan first scan of a newly connected mailbox (kept out of stats)
     * @param array|null $cursor ['uidvalidity' => int, 'last_uid' => int] from the previous scan
     * @param \DateTimeInterface|null $since used when the cursor cannot be: only mail
     *        received since then is scanned; null = the whole INBOX (first scan)
     * @param array|null $newCursor receives the cursor to store for the next scan
     *        (null when the server reports no UIDVALIDITY)
     * @param int|null $maxMessages / $deadline stop early (whole-INBOX and incremental
     *        passes with a UIDVALIDITY only - a "since" pass is short and must not
     *        leave a cursor below older mail); the cursor then points at the last
     *        processed UID and 'remaining' says how many are left
     *
     * @return array counters ('total' = messages in INBOX when the scan started,
     *               'checked' = new messages run through the pipeline, 'skipped' =
     *               looked at but already checked, 'remaining' = not reached
     *               because of the limit) + 'errors' (at most 20 strings)
     */
    public function scan(ConnectionInterface $connection, $email, ?bool $deleteSpam, bool $initialScan = false, ?array $cursor = null, ?\DateTimeInterface $since = null, ?array &$newCursor = null, ?int $maxMessages = null, ?float $deadline = null): array
    {
        $stats = ['total' => 0, 'checked' => 0, 'skipped' => 0, 'whitelisted' => 0, 'blacklisted' => 0,
                  'quarantined' => 0, 'moved_to_spam' => 0, 'remaining' => 0, 'errors' => []];

        $inbox = $connection->getMailbox('INBOX');
        try {
            $status = $inbox->getStatus(\SA_MESSAGES | \SA_UIDVALIDITY | \SA_UIDNEXT);
        } catch (\Throwable $e) {
            $status = new \stdClass(); // no cursor this time, see nextCursor()
        }
        $validity = (int)($status->uidvalidity ?? 0);
        $uidNext = (int)($status->uidnext ?? 0);

        list($mode, $uids) = $this->selectMessages($inbox, $cursor, $validity, $uidNext, $since);
        $limited = ($maxMessages !== null || $deadline !== null) && $validity > 0 && $mode !== self::MODE_SINCE;

        $firstFailed = null;
        $maxUid = 0;
        $done = 0;
        $partial = false;
        foreach ($uids as $uid) {
            if ($limited && $done > 0 && (($maxMessages !== null && $done >= $maxMessages) || ($deadline !== null && microtime(true) >= $deadline))) {
                $partial = true;
                $stats['remaining'] = count($uids) - $done;
                break;
            }
            $done++;
            $maxUid = max($maxUid, $uid);
            $event = null;
            try {
                $msg = $inbox->getMessage($uid);
                $event = new MessageEvent($msg, $email, $connection, $deleteSpam);
                $event->setInitialScan($initialScan);
                $this->dispatcher->dispatch($event, 'antispam.check.message');

                if ($event->isCheckedbefore()) {
                    $stats['skipped']++;
                    continue;
                }
                $stats['checked']++;
                if ($event->isWhitelist()) { $stats['whitelisted']++; }
                if ($event->isBlacklist()) { $stats['blacklisted']++; }
                if ($event->isDelete()) {
                    $event->isSpam() ? $stats['moved_to_spam']++ : $stats['quarantined']++;
                }
            } catch (\Throwable $e) {
                $firstFailed = $firstFailed ?? $uid;
                if (count($stats['errors']) < 20) {
                    $stats['errors'][] = 'UID ' . $uid . ': ' . $e->getMessage();
                }
            } finally {
                $this->afterMessage($event, $stats);
            }
        }

        if ($stats['moved_to_spam'] + $stats['quarantined'] > 0) {
            $connection->expunge();
        }

        // 'total' = messages in INBOX (as the panel shows it), not only the
        // new ones looked at; 'checked' are the new ones run through the pipeline.
        $stats['total'] = isset($status->messages) ? (int)$status->messages : count($uids);

        $newCursor = $partial
            ? $this->partialCursor($cursor, $validity, $maxUid, $firstFailed)
            : $this->nextCursor($mode, $cursor, $validity, $uidNext, $maxUid, $firstFailed);
        $this->messages->purgeIfDue();

        return $stats;
    }

    /** "uidvalidity:last_uid:unix time" - the legacy mailbox cursor as stored in the config table. */
    public static function encodeCursor(?array $cursor)
    {
        if ($cursor === null) {
            return null;
        }
        return (int)$cursor['uidvalidity'] . ':' . (int)$cursor['last_uid'] . ':' . (int)($cursor['scanned_at'] ?? time());
    }

    public static function decodeCursor($value)
    {
        if (!is_string($value) || !preg_match('/^(\d+):(\d+)(?::(\d+))?$/', $value, $m)) {
            return null;
        }
        return ['uidvalidity' => (int)$m[1], 'last_uid' => (int)$m[2], 'scanned_at' => isset($m[3]) ? (int)$m[3] : null];
    }

    /** Cursor value that makes the next scan read the whole INBOX once. */
    public static function fullRescanCursor()
    {
        return ['uidvalidity' => 0, 'last_uid' => 0];
    }

    /** @return array{0:string, 1:int[]} mode and ascending UIDs to run through the pipeline */
    private function selectMessages(MailboxInterface $inbox, ?array $cursor, $validity, $uidNext, ?\DateTimeInterface $since)
    {
        if ($cursor !== null && (int)$cursor['uidvalidity'] === 0) {
            $mode = self::MODE_FULL;
        } elseif ($cursor !== null && $validity > 0 && (int)$cursor['uidvalidity'] === $validity) {
            $last = (int)$cursor['last_uid'];
            if ($uidNext > 0 && $uidNext <= $last + 1) {
                return [self::MODE_INCREMENTAL, []]; // nothing new
            }
            try {
                $sequence = self::uidsOf($inbox->getMessageSequence(($last + 1) . ':*'));
            } catch (InvalidSearchCriteriaException $e) {
                $sequence = []; // empty INBOX
            }
            // "n:*" always returns the newest message, even when it is below n.
            $uids = array_filter($sequence, function ($uid) use ($last) {
                return $uid > $last;
            });
            return [self::MODE_INCREMENTAL, self::sorted($uids)];
        } elseif ($since !== null) {
            $mode = self::MODE_SINCE;
        } else {
            $mode = self::MODE_FULL;
        }

        $uids = $mode === self::MODE_SINCE
            ? self::uidsOf($inbox->getMessages(new Since($since)))
            : self::uidsOf($inbox->getMessages());
        return [$mode, self::sorted($uids)];
    }

    /** Cursor after a pass stopped by its limit: the rest (above the last processed UID) is the next call's. */
    private function partialCursor(?array $cursor, $validity, $maxUid, $firstFailed)
    {
        $last = $cursor !== null && (int)$cursor['uidvalidity'] === (int)$validity ? (int)$cursor['last_uid'] : 0;
        $next = $firstFailed !== null ? max($last, $firstFailed - 1) : max($last, $maxUid);
        return ['uidvalidity' => $validity, 'last_uid' => (int)$next, 'scanned_at' => time()];
    }

    private function nextCursor($mode, ?array $cursor, $validity, $uidNext, $maxUid, $firstFailed)
    {
        if ($validity <= 0) {
            return null; // server without UIDVALIDITY: no cursor, every scan is a "since last scan" pass
        }
        if ($mode === self::MODE_INCREMENTAL) {
            $last = (int)$cursor['last_uid'];
            $next = $firstFailed !== null ? max($last, $firstFailed - 1) : max($last, $maxUid);
        } elseif ($mode === self::MODE_FULL && $firstFailed !== null) {
            // Everything was in scope, so the failed message is retried next time.
            $next = $firstFailed - 1;
        } else {
            // A "since" pass leaves older mail alone on purpose: mail above a
            // failed UID may be old and must not be picked up later, so the
            // cursor goes past everything that existed when the pass started.
            $next = $uidNext > 0 ? max($uidNext - 1, 0) : $maxUid;
            if ($mode === self::MODE_FULL) {
                $next = max($next, $maxUid);
            }
        }
        return ['uidvalidity' => $validity, 'last_uid' => (int)$next, 'scanned_at' => time()];
    }

    /**
     * Keeps one bad message from poisoning the rest of the run: a failed
     * flush closes the EntityManager, and every later message (and account)
     * would fail with "EntityManager is closed". Also detaches the message's
     * score log so the unit of work does not grow with the INBOX.
     */
    private function afterMessage(?MessageEvent $event, array &$stats)
    {
        if (!$this->doctrine) {
            return;
        }
        $em = $this->doctrine->getManager();
        if (!$em->isOpen()) {
            $this->doctrine->resetManager();
            if (count($stats['errors']) < 20) {
                $stats['errors'][] = 'błąd zapisu do bazy - połączenie z bazą odnowione';
            }
            return;
        }
        $log = $event ? $event->getScoreLog() : null;
        if ($log !== null && $em->contains($log)) {
            $em->detach($log);
        }
    }

    private function saveAccountCursor(Account $account, ?array $cursor)
    {
        $account->setImapCursor($cursor);
        if (!$this->doctrine || $account->getId() === null) {
            return;
        }
        // Plain SQL: the caller flushes the account too, but after a reset
        // EntityManager this Account is detached and the flush would be lost.
        $this->doctrine->getConnection()->update('antispam_account', [
            'imap_uid_validity' => $cursor === null ? null : (int)$cursor['uidvalidity'],
            'imap_last_uid' => $cursor === null ? null : (int)$cursor['last_uid'],
        ], ['id' => $account->getId()]);
    }

    /** SINCE date for a cursor-less pass: a day before the last scan (IMAP SINCE has day granularity). */
    private function windowStart(?\DateTimeInterface $lastScan)
    {
        $start = $lastScan ? \DateTimeImmutable::createFromInterface($lastScan) : new \DateTimeImmutable('-' . self::FALLBACK_WINDOW_DAYS . ' days');
        return $start->modify('-1 day');
    }

    /** @return resource|null */
    private function lock($name)
    {
        if ($this->lockDir === null) {
            return null;
        }
        if (!is_dir($this->lockDir)) {
            @mkdir($this->lockDir, 0775, true);
        }
        $handle = @fopen($this->lockDir . '/imap-scan-' . sha1($name) . '.lock', 'c');
        if ($handle === false) {
            return null; // lock dir not writable: scan anyway rather than never
        }
        if (!flock($handle, LOCK_EX | LOCK_NB)) {
            fclose($handle);
            throw new ScanLockedException();
        }
        return $handle;
    }

    private function unlock($handle)
    {
        if ($handle) {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private static function uidsOf(iterable $iterator)
    {
        if ($iterator instanceof \ArrayIterator) {
            return array_map('intval', $iterator->getArrayCopy());
        }
        $uids = [];
        foreach ($iterator as $msg) {
            $uids[] = (int)$msg->getNumber();
        }
        return $uids;
    }

    private static function sorted(array $uids)
    {
        $uids = array_values(array_unique($uids));
        sort($uids, SORT_NUMERIC);
        return $uids;
    }
}
