<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\EmailWhitelist;
use Ddeboer\Imap\Search\Date\Since;
use Doctrine\ORM\EntityManagerInterface;

/**
 * One API over both quarantine back-ends:
 *
 *   - "imap"        the legacy single IMAP mailbox (QUARANTINE folder)
 *   - "imap-<id>"   an IMAP account (its QUARANTINE folder)
 *   - "ssh-<id>"    an SSH+Maildir account, handled through the agent
 *
 * Used by the quarantine digest and its one-click release / whitelist /
 * delete links. IMAP services are pulled lazily from a service locator
 * because ConnectionService logs in to IMAP as soon as it is built.
 */
class QuarantineService
{
    const IMAP_KEY = 'imap';
    const NOT_FOUND = 'Nie znaleziono wiadomości w kwarantannie (została już przywrócona lub usunięta?).';

    /**
     * Synthetic reason put on a listed message whose score log row could not
     * be found (logging off, row purged, subject/sender mismatch). Treated as
     * high risk, so "always accept" is never offered blindly (fail closed).
     */
    const REASON_SCORE_UNKNOWN = 'score_unknown';

    /** Stored subjects are clipped to this many characters (SpamScoreLog::setSubject). */
    const LOG_SUBJECT_CHARS = 500;
    /** Stored senders are clipped to this many characters. */
    const LOG_SENDER_CHARS = 255;

    /** purge() modes: every quarantined message / only the high-risk ones. */
    const PURGE_ALL = 'all';
    const PURGE_HIGH_RISK = 'high_risk';
    const PURGE_MODES = [self::PURGE_ALL, self::PURGE_HIGH_RISK];
    /** IMAP purge: expunge after this many flagged messages (bounded work per round trip). */
    const PURGE_EXPUNGE_EVERY = 100;

    private $em;
    private $config;
    private $ssh;
    private $connection;
    private $inbox;
    private $messages;
    private $imapScan;
    /** @var array<string, \Ddeboer\Imap\ConnectionInterface> open IMAP account connections */
    private $accountConnections = [];

    public function __construct(
        EntityManagerInterface $em,
        ConfigService $config,
        SshService $ssh,
        ConnectionService $connection,
        InboxService $inbox,
        MessageService $messages,
        ImapScanService $imapScan,
        private ?MailboxSettingsResolver $mailboxSettings = null,
        private ?Bayes\BayesService $bayes = null,
    ) {
        $this->imapScan = $imapScan;
        $this->em = $em;
        $this->config = $config;
        $this->ssh = $ssh;
        $this->connection = $connection;
        $this->inbox = $inbox;
        $this->messages = $messages;
    }

    /**
     * Every mailbox that has a quarantine, with its digest settings
     * (Ustawienia skrzynki override -> global):
     *   recipient       where its digest goes
     *   digest_enabled  the mailbox's own on/off, null = global switch
     *   digest_hour     0-23 = own send hour, null = global schedule
     *
     * @return array list of ['key', 'label', 'account_email', 'recipient', 'digest_enabled', 'digest_hour']
     */
    public function getMailboxes()
    {
        $out = [];
        if ($this->config->get('imap') && $this->config->get('login')) {
            $email = (string)$this->config->get('email');
            $recipient = trim((string)$this->config->get('digest.imap_recipient')) ?: $email;
            $out[] = array_replace(['key' => self::IMAP_KEY, 'label' => 'IMAP: ' . ($email ?: $this->config->get('login')), 'account_email' => $email, 'recipient' => $recipient], $this->digestSettings(null));
        }
        foreach ($this->em->getRepository(Account::class)->findBy(['connectionType' => Account::CONNECTION_IMAP]) as $account) {
            $out[] = array_replace([
                'key' => 'imap-' . $account->getId(),
                'label' => $account->getName() . ' (' . $account->getEmail() . ')',
                'account_email' => $account->getEmail(),
                'recipient' => $account->getEmail(),
            ], $this->digestSettings($account));
        }
        foreach ($this->em->getRepository(Account::class)->findBy(['connectionType' => Account::CONNECTION_SSH]) as $account) {
            if (!$account->getAgentDeployed()) {
                continue;
            }
            $out[] = array_replace([
                'key' => 'ssh-' . $account->getId(),
                'label' => $account->getName() . ' (' . $account->getEmail() . ')',
                'account_email' => $account->getEmail(),
                'recipient' => $account->getEmail(),
            ], $this->digestSettings($account));
        }
        return $out;
    }

    /** Digest part of a getMailboxes() row; a 'recipient' here replaces the default one. */
    private function digestSettings(?Account $account): array
    {
        if ($this->mailboxSettings === null) {
            return ['digest_enabled' => null, 'digest_hour' => null];
        }
        $s = $account ? $this->mailboxSettings->forAccount($account) : $this->mailboxSettings->global();
        $row = ['digest_enabled' => $s->isOverridden('digest_enabled') ? $s->digestEnabled : null, 'digest_hour' => $s->digestHour];
        if ($account && $s->isOverridden('digest_recipient')) {
            $row['recipient'] = $s->digestRecipient;
        }
        return $row;
    }

    public function getMailbox($key)
    {
        foreach ($this->getMailboxes() as $m) {
            if ($m['key'] === $key) {
                return $m;
            }
        }
        return null;
    }

    /**
     * @param \DateTimeInterface|null $since only messages received after this moment
     *
     * @return array list of ['id','from','from_name','subject','date' => \DateTimeImmutable|null,'score','reasons','uidvalidity' => int|null]
     */
    public function listItems($key, ?\DateTimeInterface $since = null, $limit = 200)
    {
        if (self::isImapKey($key)) {
            $mailbox = $this->getMailbox($key);
            return $this->listImap($this->imapConnection($key), $since, $limit, $mailbox ? (string)$mailbox['account_email'] : '');
        }
        $account = $this->sshAccount($key);
        $res = $this->ssh->quarantineList($account, $since ? $since->getTimestamp() : null, $limit);
        if (empty($res['success'])) {
            throw new \RuntimeException('Agent quarantine-list failed: ' . substr((string)($res['error'] ?? 'unknown error'), 0, 300));
        }
        $items = [];
        foreach ((array)$res['items'] as $row) {
            $score = isset($row['score']) ? $row['score'] : null;
            $reasons = (array)($row['reasons'] ?? []);
            $items[] = [
                'id' => (string)$row['id'],
                'from' => (string)($row['from'] ?? ''),
                'from_name' => (string)($row['from_name'] ?? ''),
                'subject' => (string)($row['subject'] ?? ''),
                'date' => !empty($row['date']) ? new \DateTimeImmutable($row['date']) : null,
                'score' => $score,
                // No score_log row in the agent: we don't know why it was quarantined.
                'reasons' => ($score === null && !$reasons) ? self::unknownScoreReasons() : $reasons,
                // Maildir file names are never reused, so SSH ids need no UIDVALIDITY.
                'uidvalidity' => null,
            ];
        }
        return $items;
    }

    /**
     * Move a message back to the inbox, optionally whitelisting its sender.
     *
     * @param int|null $uidValidity IMAP only: UIDVALIDITY the id was issued under (digest
     *                              links). When the folder's UIDVALIDITY changed, the UID
     *                              may now name another message, so nothing is done.
     *
     * @return array ['success' => bool, 'message' => string, 'sender' => string]
     */
    public function release($key, $id, $whitelist = false, $uidValidity = null)
    {
        $mailbox = $this->getMailbox($key);
        if (!$mailbox) {
            return ['success' => false, 'message' => 'Ta skrzynka nie jest już obsługiwana.', 'sender' => ''];
        }

        if (self::isImapKey($key)) {
            try {
                $connection = $this->imapConnection($key);
                $folder = $connection->getMailbox($this->inbox->getQuarantineFolderName());
                if (!self::uidValidityMatches($folder, $uidValidity)) {
                    return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
                }
                $msg = $folder->getMessage((int)$id);
                $sender = $msg->getFrom() ? strtolower((string)$msg->getFrom()->getAddress()) : '';
                // A released message is a "not spam" verdict for the Bayes classifier (read before the move).
                $this->bayes?->learnImap($msg, 'ham', $mailbox['account_email'] ?: null, 'quarantine');
                // Released mail must not be quarantined again on the next scan.
                $this->messages->setAsChecked($msg, $mailbox['account_email'] ?: null);
                $msg->move($connection->getMailbox('INBOX'));
                $connection->expunge();
            } catch (\Throwable $e) {
                return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
            }
        } else {
            $res = $this->ssh->quarantineAction($this->sshAccount($key), 'release', $id, $whitelist);
            if (empty($res['success'])) {
                return ['success' => false, 'message' => self::agentError($res, 'Nie udało się przywrócić wiadomości.'), 'sender' => ''];
            }
            $sender = strtolower((string)($res['sender'] ?? ''));
        }

        if ($whitelist && $sender !== '') {
            $this->whitelistSender($mailbox['account_email'], $sender);
        }

        return [
            'success' => true,
            'message' => $whitelist && $sender !== ''
                ? sprintf('Wiadomość została przywrócona do skrzynki odbiorczej. Poczta od %s nie będzie już filtrowana.', $sender)
                : 'Wiadomość została przywrócona do skrzynki odbiorczej.',
            'sender' => $sender,
        ];
    }

    /**
     * @param int|null $uidValidity see release()
     *
     * @return array ['success' => bool, 'message' => string, 'sender' => string]
     */
    public function delete($key, $id, $uidValidity = null)
    {
        if (!$this->getMailbox($key)) {
            return ['success' => false, 'message' => 'Ta skrzynka nie jest już obsługiwana.', 'sender' => ''];
        }
        if (self::isImapKey($key)) {
            try {
                $connection = $this->imapConnection($key);
                $folder = $connection->getMailbox($this->inbox->getQuarantineFolderName());
                if (!self::uidValidityMatches($folder, $uidValidity)) {
                    return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
                }
                $msg = $folder->getMessage((int)$id);
                $sender = $msg->getFrom() ? strtolower((string)$msg->getFrom()->getAddress()) : '';
                $msg->delete();
                $connection->expunge();
            } catch (\Throwable $e) {
                return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
            }
            return ['success' => true, 'message' => 'Wiadomość została usunięta.', 'sender' => $sender];
        }

        $res = $this->ssh->quarantineAction($this->sshAccount($key), 'delete', $id);
        if (empty($res['success'])) {
            return ['success' => false, 'message' => self::agentError($res, 'Nie udało się usunąć wiadomości.'), 'sender' => ''];
        }
        return ['success' => true, 'message' => 'Wiadomość została usunięta.', 'sender' => (string)($res['sender'] ?? '')];
    }

    /**
     * Bulk permanent deletion from the quarantine of one mailbox (background
     * job quarantine.purge, docs/spam-handling.md#bulk-deletion):
     *
     *   - PURGE_ALL        every message that is in the quarantine folder now;
     *   - PURGE_HIGH_RISK  only the messages QuarantineDigestService::isHighRisk()
     *                      selects - the rule that hides "Zawsze akceptuj" -
     *                      re-evaluated here, at run time, never taken from the
     *                      page the button was on (no score log row = high risk).
     *
     * Only the quarantine folder is opened (IMAP: getQuarantineFolderName(),
     * refused if it ever named INBOX / SPAM; SSH: the agent's .QUARANTINE).
     *
     * @param callable|null $progress fn(int $done, int $total): heartbeat / progress of a long IMAP pass
     *
     * @return array{total:int, deleted:int, skipped:int, failed:int, errors:string[]}
     *
     * @throws \RuntimeException mailbox gone / unreachable, agent too old or failing
     */
    public function purge(string $key, string $mode, ?callable $progress = null): array
    {
        if (!in_array($mode, self::PURGE_MODES, true)) {
            throw new \InvalidArgumentException('Unknown quarantine purge mode: ' . $mode);
        }
        $mailbox = $this->getMailbox($key);
        if (!$mailbox) {
            throw new \RuntimeException('Ta skrzynka nie jest już obsługiwana.');
        }

        if (!self::isImapKey($key)) {
            $res = $this->ssh->quarantinePurge($this->sshAccount($key), $mode);
            if (empty($res['success'])) {
                throw new \RuntimeException('Agent quarantine-purge: ' . mb_substr((string)($res['error'] ?? 'unknown error'), 0, 300));
            }
            return [
                'total' => (int)($res['total'] ?? 0),
                'deleted' => (int)($res['deleted'] ?? 0),
                'skipped' => (int)($res['skipped'] ?? 0),
                'failed' => (int)($res['failed'] ?? 0),
                'errors' => array_slice(array_map('strval', (array)($res['errors'] ?? [])), 0, 20),
            ];
        }

        return $this->purgeImap($this->imapConnection($key), $mode, (string)$mailbox['account_email'], $progress);
    }

    private function purgeImap($connection, string $mode, string $accountEmail, ?callable $progress): array
    {
        $out = ['total' => 0, 'deleted' => 0, 'skipped' => 0, 'failed' => 0, 'errors' => []];
        $name = $this->inbox->getQuarantineFolderName();
        foreach (['INBOX', $this->inbox->getSpamFolderName()] as $forbidden) {
            if (strcasecmp(trim((string)$name), (string)$forbidden) === 0) {
                throw new \LogicException('Refusing to purge ' . $name . ': not the quarantine folder');
            }
        }
        if (!$connection->hasMailbox($name)) {
            return $out;
        }
        $folder = $connection->getMailbox($name);

        // What is in the quarantine right now (UIDs of this session).
        $items = [];
        foreach ($folder->getMessages() as $msg) {
            $out['total']++;
            if ($mode === self::PURGE_ALL) {
                $items[] = ['msg' => $msg];
                continue;
            }
            try {
                $from = $msg->getFrom();
                $items[] = ['msg' => $msg, 'from' => $from ? strtolower((string)$from->getAddress()) : '', 'subject' => (string)$msg->getSubject()];
            } catch (\Throwable $e) {
                // Unreadable: not listed on the page either, so not judged - kept.
                $out['skipped']++;
            }
        }

        if ($mode === self::PURGE_HIGH_RISK) {
            $risky = [];
            foreach (array_chunk($items, 200) as $chunk) {
                foreach ($this->attachImapScores($chunk, $accountEmail) as $item) {
                    if (QuarantineDigestService::isHighRisk($item['reasons'])) {
                        $risky[] = $item;
                    } else {
                        $out['skipped']++;
                    }
                }
            }
            $items = $risky;
        }

        $total = count($items);
        $flagged = 0;
        foreach ($items as $i => $item) {
            try {
                $item['msg']->delete();
                $out['deleted']++;
                $flagged++;
            } catch (\Throwable $e) {
                $out['failed']++;
                if (count($out['errors']) < 20) {
                    $out['errors'][] = 'UID ' . $item['msg']->getNumber() . ': ' . mb_substr($e->getMessage(), 0, 200);
                }
            }
            if ($flagged >= self::PURGE_EXPUNGE_EVERY) {
                $connection->expunge();
                $flagged = 0;
            }
            if ($progress && ($i + 1) % 50 === 0) {
                $progress($i + 1, $total);
            }
        }
        if ($flagged > 0) {
            $connection->expunge();
        }
        $progress && $progress($total, $total);
        return $out;
    }

    /**
     * Add an exact e-mail whitelist rule for $sender on $accountEmail (no-op
     * when one already exists).
     */
    public function whitelistSender($accountEmail, $sender)
    {
        $repo = $this->em->getRepository(EmailWhitelist::class);
        if ($repo->findOneBy(['email' => $accountEmail, 'whitelistemail' => $sender])) {
            return false;
        }
        $rule = new EmailWhitelist();
        $rule->setEmail($accountEmail)
            ->setWhitelistemail($sender)
            ->setPatternType(EmailWhitelist::PATTERN_EXACT);
        $this->em->persist($rule);
        $this->em->flush();
        return true;
    }

    private static function isImapKey($key)
    {
        return $key === self::IMAP_KEY || preg_match('/^imap-\d+\z/', (string)$key);
    }

    /** Connection of the legacy mailbox or of an IMAP account ("imap-<id>"). */
    private function imapConnection($key)
    {
        if ($key === self::IMAP_KEY) {
            return $this->connection->getConnection();
        }
        if (!isset($this->accountConnections[$key])) {
            $account = $this->em->getRepository(Account::class)->find((int)substr((string)$key, 5));
            if (!$account || !$account->isImap()) {
                throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
            }
            $this->accountConnections[$key] = $this->imapScan->connect($account);
        }
        return $this->accountConnections[$key];
    }

    private function listImap($connection, ?\DateTimeInterface $since = null, $limit = 200, $accountEmail = '')
    {
        $items = [];
        $folder = $this->inbox->getQuarantineFolderName();
        if (!$connection->hasMailbox($folder)) {
            return [];
        }
        $mailbox = $connection->getMailbox($folder);
        $uidValidity = self::folderUidValidity($mailbox);
        // SINCE works on the server's INTERNALDATE with day granularity (in the
        // server's time zone, hence one day of slack); the exact cut-off is below.
        $messages = $since
            ? $mailbox->getMessages(new Since(\DateTimeImmutable::createFromInterface($since)->modify('-1 day')))
            : $mailbox->getMessages();
        foreach ($messages as $msg) {
            try {
                $date = $msg->getDate();
                // Arrival time on the server, not the sender-controlled Date: header.
                $arrived = self::internalDate($msg) ?? $date;
                if ($since && $arrived && $arrived < $since) {
                    continue;
                }
                $from = $msg->getFrom();
                $items[] = [
                    'id' => (string)$msg->getNumber(),
                    'from' => $from ? strtolower((string)$from->getAddress()) : '',
                    'from_name' => $from ? (string)$from->getName() : '',
                    'subject' => (string)$msg->getSubject(),
                    'date' => $date,
                    'score' => null,
                    'reasons' => [],
                    'uidvalidity' => $uidValidity,
                ];
            } catch (\Throwable $e) {
                continue;
            }
        }
        usort($items, function ($a, $b) {
            return ($b['date'] ? $b['date']->getTimestamp() : 0) - ($a['date'] ? $a['date']->getTimestamp() : 0);
        });
        return $this->attachImapScores(array_slice($items, 0, $limit), $accountEmail);
    }

    /**
     * IMAP quarantine has no stable link to the score log, so match the most
     * recent quarantine decision of the same mailbox with the same sender +
     * subject. One query per listing (idx_account_sender), not one per item.
     *
     * Fail closed: an item without a matching row gets REASON_SCORE_UNKNOWN,
     * which QuarantineDigestService::isHighRisk() treats as high risk, so no
     * "always accept" is offered for it.
     */
    public function attachImapScores(array $items, $accountEmail)
    {
        $senders = [];
        foreach ($items as $item) {
            $senders[] = self::clipSender($item['from']);
        }
        $logs = $this->em->getRepository(SpamScoreLog::class)->findQuarantineBySenders($accountEmail, $senders);

        foreach ($items as &$item) {
            $item['score'] = null;
            $item['reasons'] = self::unknownScoreReasons();
            $sender = self::clipSender($item['from']);
            foreach ($logs as $log) {
                if (strtolower((string)$log->getSender()) === $sender && self::subjectMatches($log->getSubject(), $item['subject'])) {
                    $reasons = $log->getReasonsDecoded();
                    $item['score'] = $log->getScore();
                    $item['reasons'] = is_array($reasons) && $reasons ? $reasons : self::unknownScoreReasons();
                    break;
                }
            }
        }
        unset($item);
        return $items;
    }

    /** @return array a reasons list holding only the REASON_SCORE_UNKNOWN marker */
    public static function unknownScoreReasons()
    {
        return [['rule' => self::REASON_SCORE_UNKNOWN, 'score' => 0]];
    }

    private static function clipSender($sender)
    {
        return mb_substr(strtolower((string)$sender), 0, self::LOG_SENDER_CHARS, 'UTF-8');
    }

    /**
     * Stored subject vs. the subject read from the quarantine. Rows are clipped
     * to 500 characters (mb-safe); older rows were clipped to 500 bytes, and
     * MySQL may have dropped the split trailing character - all of these match.
     */
    public static function subjectMatches($stored, $subject)
    {
        $stored = (string)$stored;
        $subject = (string)$subject;
        if ($stored === $subject || $stored === mb_substr($subject, 0, self::LOG_SUBJECT_CHARS, 'UTF-8')) {
            return true;
        }
        $bytes = substr($subject, 0, self::LOG_SUBJECT_CHARS);
        if ($stored === $bytes) {
            return true;
        }
        return strlen($stored) >= self::LOG_SUBJECT_CHARS - 3 && str_starts_with($bytes, $stored);
    }

    /** UIDVALIDITY of an open IMAP folder, null when the server doesn't report it. */
    private static function folderUidValidity($mailbox)
    {
        try {
            $status = $mailbox->getStatus(\SA_UIDVALIDITY);
            return isset($status->uidvalidity) ? (int)$status->uidvalidity : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /** No expected value (panel actions on a live listing) means nothing to check. */
    private static function uidValidityMatches($mailbox, $expected)
    {
        if ($expected === null) {
            return true;
        }
        $current = self::folderUidValidity($mailbox);
        return $current !== null && $current === (int)$expected;
    }

    /** INTERNALDATE (server arrival time) of a message, or null. */
    private static function internalDate($msg)
    {
        try {
            $raw = $msg->getHeaders()->get('maildate');
            return is_string($raw) && trim($raw) !== '' ? new \DateTimeImmutable($raw) : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * End-user message for a failed agent call. Raw agent output (paths, PHP
     * errors) is never shown on the public page.
     */
    private static function agentError(array $res, $fallback)
    {
        if (stripos((string)($res['error'] ?? ''), 'not found') !== false) {
            return self::NOT_FOUND;
        }
        return $fallback;
    }

    private function sshAccount($key)
    {
        if (!preg_match('/^ssh-(\d+)$/', (string)$key, $m)) {
            throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
        }
        $account = $this->em->getRepository(Account::class)->find((int)$m[1]);
        if (!$account || !$account->isSsh()) {
            throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
        }
        return $account;
    }
}
