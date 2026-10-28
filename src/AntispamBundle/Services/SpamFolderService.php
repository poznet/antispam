<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\SpamScoreLog;
use Doctrine\ORM\EntityManagerInterface;

/**
 * SPAM folder of the mailboxes known to QuarantineService (same keys: "imap"
 * legacy, "imap-<id>", "ssh-<id>") for the user area /my/spam: list the
 * newest messages and release one back to INBOX, optionally whitelisting the
 * sender ("Przywróć i zawsze akceptuj").
 *
 * A released message is marked as checked (IMAP: MessageService marker;
 * SSH: the agent's `checked` table), so the next scan does not move it back.
 * Ownership of the key is the caller's job (Security\MailboxAccess).
 */
class SpamFolderService
{
    public const NOT_FOUND = 'Nie znaleziono wiadomości w folderze SPAM (została już przywrócona lub usunięta?).';
    public const DEFAULT_LIMIT = 100;

    /** @var array<string, \Ddeboer\Imap\ConnectionInterface> */
    private array $connections = [];

    public function __construct(
        private EntityManagerInterface $em,
        private QuarantineService $quarantine,
        private SshService $ssh,
        private ImapScanService $imapScan,
        private ConnectionService $legacyConnection,
        private InboxService $inbox,
        private MessageService $messages,
        private ?Bayes\BayesService $bayes = null,
    ) {
    }

    /**
     * @return array{items: array, total: int} items: ['id','from','from_name','subject','date','score','reasons','uidvalidity']
     */
    public function listItems(string $key, int $limit = self::DEFAULT_LIMIT): array
    {
        $mailbox = $this->quarantine->getMailbox($key);
        if (!$mailbox) {
            throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
        }
        if (self::isImapKey($key)) {
            return $this->listImap($this->imapConnection($key), $limit, (string)$mailbox['account_email']);
        }

        $res = $this->ssh->spamList($this->sshAccount($key), $limit);
        if (empty($res['success'])) {
            throw new \RuntimeException('Agent spam-list failed: ' . substr((string)($res['error'] ?? 'unknown error'), 0, 300));
        }
        $items = [];
        foreach ((array)($res['items'] ?? []) as $row) {
            $score = $row['score'] ?? null;
            $reasons = (array)($row['reasons'] ?? []);
            $items[] = [
                'id' => (string)$row['id'],
                'from' => (string)($row['from'] ?? ''),
                'from_name' => (string)($row['from_name'] ?? ''),
                'subject' => (string)($row['subject'] ?? ''),
                'date' => !empty($row['date']) ? new \DateTimeImmutable($row['date']) : null,
                'score' => $score,
                'reasons' => ($score === null && !$reasons) ? QuarantineService::unknownScoreReasons() : $reasons,
                'uidvalidity' => null,
            ];
        }
        return ['items' => $items, 'total' => (int)($res['total'] ?? count($items))];
    }

    /**
     * @param int|null $uidValidity IMAP: UIDVALIDITY of the listing the id came from
     *
     * @return array ['success' => bool, 'message' => string, 'sender' => string]
     */
    public function release(string $key, string $id, bool $whitelist = false, ?int $uidValidity = null): array
    {
        $mailbox = $this->quarantine->getMailbox($key);
        if (!$mailbox) {
            return ['success' => false, 'message' => 'Ta skrzynka nie jest już obsługiwana.', 'sender' => ''];
        }

        if (self::isImapKey($key)) {
            if (!preg_match('/^\d{1,10}$/', $id)) {
                return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
            }
            try {
                $connection = $this->imapConnection($key);
                $name = $this->inbox->getSpamFolderName();
                if (!$connection->hasMailbox($name)) {
                    return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
                }
                $folder = $connection->getMailbox($name);
                if ($uidValidity !== null && self::folderUidValidity($folder) !== $uidValidity) {
                    return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
                }
                $msg = $folder->getMessage((int)$id);
                $sender = $msg->getFrom() ? strtolower((string)$msg->getFrom()->getAddress()) : '';
                // Released from SPAM = "not spam" for the Bayes classifier (read before the move).
                $this->bayes?->learnImap($msg, 'ham', $mailbox['account_email'] ?: null, 'spam_release');
                $this->messages->setAsChecked($msg, $mailbox['account_email'] ?: null);
                $msg->move($connection->getMailbox('INBOX'));
                $connection->expunge();
            } catch (\Throwable $e) {
                return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
            }
        } else {
            $res = $this->ssh->spamRelease($this->sshAccount($key), $id, $whitelist);
            if (empty($res['success'])) {
                $error = (string)($res['error'] ?? '');
                return ['success' => false, 'message' => stripos($error, 'not found') !== false ? self::NOT_FOUND
                    : (stripos($error, 'nie obsługuje') !== false
                        ? 'Agent na serwerze tej skrzynki jest w starszej wersji - poproś administratora o jego aktualizację.'
                        : 'Nie udało się przywrócić wiadomości.'), 'sender' => ''];
            }
            $sender = strtolower((string)($res['sender'] ?? ''));
        }

        $whitelisted = false;
        if ($whitelist && $sender !== '') {
            $this->quarantine->whitelistSender($mailbox['account_email'], $sender);
            $whitelisted = true;
        }

        return [
            'success' => true,
            'message' => $whitelisted
                ? sprintf('Wiadomość wróciła do skrzynki odbiorczej. Poczta od %s nie będzie już filtrowana.', $sender)
                : 'Wiadomość wróciła do skrzynki odbiorczej.',
            'sender' => $sender,
            'whitelisted' => $whitelisted,
        ];
    }

    private function listImap($connection, int $limit, string $accountEmail): array
    {
        $name = $this->inbox->getSpamFolderName();
        if (!$connection->hasMailbox($name)) {
            return ['items' => [], 'total' => 0];
        }
        $folder = $connection->getMailbox($name);
        $uidValidity = self::folderUidValidity($folder);

        // Newest first by UID (arrival order in the folder); only $limit are read.
        $uids = array_map('intval', $folder->getMessages()->getArrayCopy());
        rsort($uids, SORT_NUMERIC);
        $items = [];
        foreach (array_slice($uids, 0, $limit) as $uid) {
            try {
                $msg = $folder->getMessage($uid);
                $from = $msg->getFrom();
                $items[] = [
                    'id' => (string)$uid,
                    'from' => $from ? strtolower((string)$from->getAddress()) : '',
                    'from_name' => $from ? (string)$from->getName() : '',
                    'subject' => (string)$msg->getSubject(),
                    'date' => $msg->getDate(),
                    'score' => null,
                    'reasons' => [],
                    'uidvalidity' => $uidValidity,
                ];
            } catch (\Throwable $e) {
                continue;
            }
        }
        return ['items' => $this->attachScores($items, $accountEmail), 'total' => count($uids)];
    }

    /**
     * Score + reasons of the newest "spam" decision of the same mailbox with
     * the same sender and subject (like QuarantineService::attachImapScores).
     * No row = score_unknown, which counts as high risk (fail closed).
     */
    public function attachScores(array $items, string $accountEmail): array
    {
        $senders = array_map(fn($i) => mb_substr(strtolower((string)$i['from']), 0, QuarantineService::LOG_SENDER_CHARS, 'UTF-8'), $items);
        $logs = $this->em->getRepository(SpamScoreLog::class)->findDecisionsBySenders($accountEmail, $senders, SpamScoreLog::DECISION_SPAM);
        foreach ($items as $n => $item) {
            $items[$n]['score'] = null;
            $items[$n]['reasons'] = QuarantineService::unknownScoreReasons();
            foreach ($logs as $log) {
                if (strtolower((string)$log->getSender()) === $senders[$n] && QuarantineService::subjectMatches($log->getSubject(), $item['subject'])) {
                    $reasons = $log->getReasonsDecoded();
                    $items[$n]['score'] = $log->getScore();
                    $items[$n]['reasons'] = is_array($reasons) && $reasons ? $reasons : QuarantineService::unknownScoreReasons();
                    break;
                }
            }
        }
        return $items;
    }

    private static function isImapKey(string $key): bool
    {
        return $key === QuarantineService::IMAP_KEY || preg_match('/^imap-\d+\z/', $key) === 1;
    }

    private function imapConnection(string $key)
    {
        if ($key === QuarantineService::IMAP_KEY) {
            return $this->legacyConnection->getConnection();
        }
        if (!isset($this->connections[$key])) {
            $account = $this->em->getRepository(Account::class)->find((int)substr($key, 5));
            if (!$account || !$account->isImap()) {
                throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
            }
            $this->connections[$key] = $this->imapScan->connect($account);
        }
        return $this->connections[$key];
    }

    private function sshAccount(string $key): Account
    {
        if (!preg_match('/^ssh-(\d+)\z/', $key, $m)) {
            throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
        }
        $account = $this->em->getRepository(Account::class)->find((int)$m[1]);
        if (!$account || !$account->isSsh()) {
            throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
        }
        return $account;
    }

    private static function folderUidValidity($mailbox): ?int
    {
        try {
            $status = $mailbox->getStatus(\SA_UIDVALIDITY);
            return isset($status->uidvalidity) ? (int)$status->uidvalidity : null;
        } catch (\Throwable $e) {
            return null;
        }
    }
}
