<?php

namespace AntispamBundle\Imap;

use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\ImapResourceInterface;
use Ddeboer\Imap\MailboxInterface;

/**
 * ddeboer ConnectionInterface on top of ImapClient, so the scan pipeline,
 * quarantine, SPAM folder and retroactive blacklist work unchanged for
 * accounts that log in with OAuth2 (XOAUTH2).
 *
 * Moves use UID MOVE when the server has it (Gmail, Microsoft 365 do);
 * otherwise COPY + \Deleted, removed by expunge() like with ext-imap.
 * expunge() only removes messages this connection flagged, when the server
 * supports UIDPLUS.
 */
final class SocketConnection implements ConnectionInterface
{
    /** @var array<string, int[]> mailbox => UIDs flagged \Deleted by this connection */
    private array $pendingExpunge = [];
    /** @var array<string, SocketMailbox>|null */
    private ?array $mailboxes = null;

    public function __construct(private ImapClient $client)
    {
    }

    public function client(): ImapClient
    {
        return $this->client;
    }

    public function getResource(): ImapResourceInterface
    {
        throw new \LogicException('OAuth2 IMAP connections have no ext-imap resource');
    }

    public function expunge(): bool
    {
        foreach ($this->pendingExpunge as $mailbox => $uids) {
            $this->client->select($mailbox);
            $this->client->expunge(array_values($uids));
        }
        $this->pendingExpunge = [];
        return true;
    }

    public function close(int $flag = 0): bool
    {
        $this->client->logout();
        return true;
    }

    public function ping(): bool
    {
        return $this->client->noop();
    }

    public function getQuota(string $root = 'INBOX'): array
    {
        return [];
    }

    /** @return array<string, MailboxInterface> */
    public function getMailboxes(): array
    {
        if ($this->mailboxes === null) {
            $this->mailboxes = [];
            foreach ($this->client->listMailboxes('*') as $info) {
                $this->mailboxes[$info['name']] = new SocketMailbox($this, $info['name'], $info['delimiter'], $info['attributes']);
            }
        }
        return $this->mailboxes;
    }

    public function hasMailbox(string $name): bool
    {
        return $this->find($name) !== null;
    }

    public function getMailbox(string $name): MailboxInterface
    {
        $mailbox = $this->find($name);
        if ($mailbox === null) {
            throw new ImapException(sprintf('Folder "%s" nie istnieje', $name));
        }
        return $mailbox;
    }

    public function createMailbox(string $name): MailboxInterface
    {
        $this->client->createMailbox($name);
        $this->mailboxes = null;
        return $this->getMailbox($name);
    }

    public function deleteMailbox(MailboxInterface $mailbox): void
    {
        $this->client->deleteMailbox($mailbox->getName());
        unset($this->pendingExpunge[$mailbox->getName()]);
        $this->mailboxes = null;
    }

    public function count(): int
    {
        return count($this->getMailboxes());
    }

    // ---- used by SocketMailbox / SocketMessage ----------------------------------

    /** @param int[] $uids */
    public function moveUids(string $from, array $uids, string $to): void
    {
        if (!$uids) {
            return;
        }
        $this->client->select($from);
        if ($this->client->hasCapability('MOVE')) {
            $this->client->uidMove($uids, $to);
            return;
        }
        $this->client->uidCopy($uids, $to);
        $this->flagDeleted($from, $uids);
    }

    /** @param int[] $uids */
    public function copyUids(string $from, array $uids, string $to): void
    {
        if ($uids) {
            $this->client->select($from);
            $this->client->uidCopy($uids, $to);
        }
    }

    /** @param int[] $uids */
    public function flagDeleted(string $mailbox, array $uids): void
    {
        $this->client->select($mailbox);
        $this->client->uidStore($uids, '+FLAGS.SILENT', ['\\Deleted']);
        foreach ($uids as $uid) {
            $this->pendingExpunge[$mailbox][(int)$uid] = (int)$uid;
        }
    }

    /** @param int[] $uids */
    public function unflagDeleted(string $mailbox, array $uids): void
    {
        $this->client->select($mailbox);
        $this->client->uidStore($uids, '-FLAGS.SILENT', ['\\Deleted']);
        foreach ($uids as $uid) {
            unset($this->pendingExpunge[$mailbox][(int)$uid]);
        }
    }

    public function forgetMailboxes(): void
    {
        $this->mailboxes = null;
    }

    private function find(string $name): ?SocketMailbox
    {
        $mailboxes = $this->getMailboxes();
        if (isset($mailboxes[$name])) {
            return $mailboxes[$name];
        }
        // INBOX is case-insensitive (RFC 3501 5.1).
        if (strcasecmp($name, 'INBOX') === 0) {
            foreach ($mailboxes as $key => $mailbox) {
                if (strcasecmp($key, 'INBOX') === 0) {
                    return $mailbox;
                }
            }
        }
        return null;
    }
}
