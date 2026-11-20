<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Whitelist;
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
        private ?\Psr\Log\LoggerInterface $logger = null,
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
                $name = $this->inbox->getSpamFolderName($connection);
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
                $this->moveToInbox($connection, $msg);
            } catch (\Throwable $e) {
                $this->logger?->warning('Spam release failed', ['mailbox' => $key, 'id' => $id, 'error' => $e->getMessage()]);
                return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => '', 'error' => $e->getMessage()];
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

    /**
     * SPAM -> INBOX without the spam marks (SpamTagCleaner: "[SPAM]" subject
     * tag, X-Spam-Flag) and with the original date: a message with marks is
     * re-added to INBOX (APPEND with the message's Date as INTERNALDATE, the
     * \\Seen flag kept) and removed from SPAM; one without marks is moved (MOVE /
     * COPY keep INTERNALDATE). The junk keywords ($Junk, Junk) set by mail
     * clients are cleared first. A failed APPEND falls back to the plain move.
     */
    private function moveToInbox($connection, $msg): void
    {
        $inbox = $connection->getMailbox('INBOX');
        try {
            $msg->clearFlag('$Junk Junk');
        } catch (\Throwable) {
            // keywords not supported by the server
        }
        $clean = null;
        try {
            $clean = SpamTagCleaner::clean($msg->getRawMessage());
        } catch (\Throwable) {
        }
        if ($clean !== null) {
            try {
                $seen = false;
                try {
                    $seen = $msg->isSeen();
                } catch (\Throwable) {
                }
                $date = null;
                try {
                    $date = $msg->getDate();
                } catch (\Throwable) {
                }
                $inbox->addMessage($clean, $seen ? '\\Seen' : null, $date);
                $msg->delete();
                $connection->expunge();
                return;
            } catch (\Throwable) {
                // APPEND refused (size, quota): the original message is still in SPAM, move it as is
            }
        }
        $msg->move($inbox);
        $connection->expunge();
    }

    /**
     * Normalised domain pattern for "Przywróć z domeny": "firma.pl" (that
     * domain only) or "*.firma.pl" (the domain and every subdomain); also
     * accepts "@firma.pl" / "*@firma.pl". null = not a domain.
     */
    public static function domainPattern(string $input): ?string
    {
        $p = strtolower(trim($input));
        $p = (string)preg_replace('/^\*?@/', '', $p);
        $wild = str_starts_with($p, '*.');
        $base = $wild ? substr($p, 2) : $p;
        $base = rtrim($base, '.');
        if (!preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/', $base)) {
            return null;
        }
        return ($wild ? '*.' : '') . $base;
    }

    /** Does the sender address belong to the domain pattern (see domainPattern())? */
    public static function senderInDomain(string $sender, string $pattern): bool
    {
        $at = strrpos($sender, '@');
        if ($at === false) {
            return false;
        }
        $domain = rtrim(strtolower(substr($sender, $at + 1)), '.>');
        if (str_starts_with($pattern, '*.')) {
            $base = substr($pattern, 2);
            return $domain === $base || str_ends_with($domain, '.' . $base);
        }
        return $domain === $pattern;
    }

    /** At most this many messages per "Przywróć z domeny". */
    public const DOMAIN_RELEASE_LIMIT = 500;

    /**
     * "Przywróć z domeny": every message of the mailbox's SPAM folder from the
     * domain pattern back to INBOX (like release()). High-risk messages
     * (phishing, virus, unknown score) are skipped - they can still be
     * released one by one. $whitelist adds the domain to the mailbox owner's
     * domain whitelist ("firma.pl" exact, "*.firma.pl" also the wildcard
     * rule); free-mail domains (gmail.com, wp.pl…) are never whitelisted.
     *
     * @return array{success: bool, message: string, released: int, skipped: int, failed: int, whitelisted: bool}
     */
    public function releaseDomain(string $key, string $pattern, bool $whitelist = false): array
    {
        $out = ['success' => false, 'message' => '', 'released' => 0, 'skipped' => 0, 'failed' => 0, 'whitelisted' => false];
        $mailbox = $this->quarantine->getMailbox($key);
        $pattern = self::domainPattern($pattern);
        if (!$mailbox || $pattern === null) {
            $out['message'] = $pattern === null ? 'Podaj domenę, np. firma.pl albo *.firma.pl (z subdomenami).' : 'Ta skrzynka nie jest już obsługiwana.';
            return $out;
        }
        $base = ltrim($pattern, '*.');
        $freemail = DomainHelper::isFreemail($base);

        $ids = [];
        foreach ($this->listItems($key, self::DOMAIN_RELEASE_LIMIT)['items'] as $item) {
            if (!self::senderInDomain((string)$item['from'], $pattern)) {
                continue;
            }
            // The domain was picked explicitly: only a real high-risk reason (phishing,
            // virus) is skipped. A message without a score log row (moved by the mail
            // server's own filter, purged log) is released - skipping those made the
            // button a no-op for whole mailboxes.
            if (QuarantineDigestService::isPurgeableHighRisk($item['reasons'])) {
                $out['skipped']++;
                continue;
            }
            $ids[] = ['id' => (string)$item['id'], 'uidvalidity' => $item['uidvalidity']];
        }

        if (self::isImapKey($key)) {
            foreach ($ids as $row) {
                $r = $this->release($key, $row['id'], false, $row['uidvalidity']);
                $r['success'] ? $out['released']++ : $out['failed']++;
                if (!$r['success']) {
                    $this->logger?->warning('Spam domain release failed', ['mailbox' => $key, 'id' => $row['id'], 'error' => $r['error'] ?? $r['message']]);
                }
            }
        } elseif ($ids) {
            $account = $this->sshAccount($key);
            foreach (array_chunk(array_column($ids, 'id'), 100) as $chunk) {
                $res = $this->ssh->spamReleaseMany($account, $chunk);
                if (!empty($res['success']) && isset($res['released'])) {
                    $out['released'] += count((array)$res['released']);
                    $out['failed'] += count((array)($res['failed'] ?? []));
                    continue;
                }
                foreach ($chunk as $id) { // agent older than 3.11: one call per message
                    $r = $this->release($key, $id);
                    $r['success'] ? $out['released']++ : $out['failed']++;
                }
            }
        }

        if ($whitelist && !$freemail) {
            $owner = (string)$mailbox['account_email'];
            $this->quarantine->whitelistDomain($owner, $base, Whitelist::PATTERN_EXACT);
            if (str_starts_with($pattern, '*.')) {
                $this->quarantine->whitelistDomain($owner, $pattern, Whitelist::PATTERN_WILDCARD);
            }
            $out['whitelisted'] = true;
        }

        // Nothing moved although messages matched = not a success (no green flash).
        $out['success'] = $out['released'] > 0 || (!$out['failed'] && !$out['skipped']);
        $msg = sprintf('Przywrócono z domeny %s: %d.', $pattern, $out['released']);
        if ($out['skipped']) {
            $msg .= sprintf(' Pominięto %d o wysokim ryzyku (phishing lub wirus) - przywróć je pojedynczo, jeśli na pewno są potrzebne.', $out['skipped']);
        }
        if ($out['failed']) {
            $msg .= sprintf(' Nie udało się: %d.', $out['failed']);
        }
        if ($out['whitelisted']) {
            $msg .= sprintf(' Poczta z %s nie będzie już filtrowana.', $pattern);
        } elseif ($whitelist && $freemail) {
            $msg .= sprintf(' %s to darmowa poczta (każdy może mieć tam adres) - domena nie została dodana do zaufanych; dodaj pojedynczych nadawców.', $base);
        }
        if (!$ids && !$out['skipped']) {
            $msg = sprintf('W folderze SPAM nie ma wiadomości z domeny %s.', $pattern);
        }
        $out['message'] = $msg;
        return $out;
    }

    private function listImap($connection, int $limit, string $accountEmail): array
    {
        $name = $this->inbox->getSpamFolderName($connection);
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
