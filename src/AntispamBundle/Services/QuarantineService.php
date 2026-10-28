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
    const NOT_FOUND = 'Nie znaleziono wiadomości w kwarantannie (została już dostarczona lub usunięta?).';

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
        ImapScanService $imapScan
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
     * Every mailbox that has a quarantine, with the address its digest goes to.
     *
     * @return array list of ['key', 'label', 'account_email', 'recipient']
     */
    public function getMailboxes()
    {
        $out = [];
        if ($this->config->get('imap') && $this->config->get('login')) {
            $email = (string)$this->config->get('email');
            $recipient = trim((string)$this->config->get('digest.imap_recipient')) ?: $email;
            $out[] = ['key' => self::IMAP_KEY, 'label' => 'IMAP: ' . ($email ?: $this->config->get('login')), 'account_email' => $email, 'recipient' => $recipient];
        }
        foreach ($this->em->getRepository(Account::class)->findBy(['connectionType' => Account::CONNECTION_IMAP]) as $account) {
            $out[] = [
                'key' => 'imap-' . $account->getId(),
                'label' => $account->getName() . ' (' . $account->getEmail() . ')',
                'account_email' => $account->getEmail(),
                'recipient' => $account->getEmail(),
            ];
        }
        foreach ($this->em->getRepository(Account::class)->findBy(['connectionType' => Account::CONNECTION_SSH]) as $account) {
            if (!$account->getAgentDeployed()) {
                continue;
            }
            $out[] = [
                'key' => 'ssh-' . $account->getId(),
                'label' => $account->getName() . ' (' . $account->getEmail() . ')',
                'account_email' => $account->getEmail(),
                'recipient' => $account->getEmail(),
            ];
        }
        return $out;
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
                // Released mail must not be quarantined again on the next scan.
                $this->messages->setAsChecked($msg);
                $msg->move($connection->getMailbox('INBOX'));
                $connection->expunge();
            } catch (\Throwable $e) {
                return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
            }
        } else {
            $res = $this->ssh->quarantineAction($this->sshAccount($key), 'release', $id, $whitelist);
            if (empty($res['success'])) {
                return ['success' => false, 'message' => self::agentError($res, 'Nie udało się dostarczyć wiadomości.'), 'sender' => ''];
            }
            $sender = strtolower((string)($res['sender'] ?? ''));
        }

        if ($whitelist && $sender !== '') {
            $this->whitelistSender($mailbox['account_email'], $sender);
        }

        return [
            'success' => true,
            'message' => $whitelist && $sender !== ''
                ? sprintf('Wiadomość została dostarczona do skrzynki odbiorczej. Poczta od %s nie będzie już filtrowana.', $sender)
                : 'Wiadomość została dostarczona do skrzynki odbiorczej.',
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
