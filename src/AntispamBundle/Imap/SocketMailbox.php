<?php

namespace AntispamBundle\Imap;

use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\MessageInterface;
use Ddeboer\Imap\MessageIteratorInterface;
use Ddeboer\Imap\Search\ConditionInterface;

/**
 * ddeboer MailboxInterface for SocketConnection. Message numbers are UIDs,
 * as with ddeboer (which always passes FT_UID / SE_UID).
 */
final class SocketMailbox implements MailboxInterface
{
    /** LIST attribute -> c-client LATT_* bit (same values as ext-imap). */
    private const ATTRIBUTES = [
        '\\NOINFERIORS' => 1,
        '\\NOSELECT' => 2,
        '\\MARKED' => 4,
        '\\UNMARKED' => 8,
        '\\REFERRAL' => 16,
        '\\HASCHILDREN' => 32,
        '\\HASNOCHILDREN' => 64,
    ];

    /** @param string[] $attributes */
    public function __construct(
        private SocketConnection $connection,
        private string $name,
        private string $delimiter = '/',
        private array $attributes = [],
    ) {
    }

    public function connection(): SocketConnection
    {
        return $this->connection;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function renameTo(string $name): bool
    {
        $this->connection->client()->renameMailbox($this->name, $name);
        $this->connection->forgetMailboxes();
        $this->name = $name;
        return true;
    }

    public function getEncodedName(): string
    {
        return trim(ImapClient::quoteMailbox($this->name), '"');
    }

    public function getFullEncodedName(): string
    {
        return $this->getEncodedName();
    }

    public function getAttributes(): int
    {
        $bits = 0;
        foreach ($this->attributes as $attribute) {
            $bits |= self::ATTRIBUTES[strtoupper($attribute)] ?? 0;
        }
        return $bits;
    }

    public function getDelimiter(): string
    {
        return $this->delimiter;
    }

    /** Same fields as imap_status(): messages, recent, unseen, uidnext, uidvalidity, flags. */
    public function getStatus(?int $flags = null): \stdClass
    {
        $status = (object)$this->connection->client()->status($this->name);
        $status->flags = $flags ?? 0;
        return $status;
    }

    public function setFlag(string $flag, $numbers): bool
    {
        $this->connection->client()->select($this->name);
        $this->connection->client()->uidStore(self::uids($numbers), '+FLAGS.SILENT', preg_split('/\s+/', trim($flag)));
        return true;
    }

    public function clearFlag(string $flag, $numbers): bool
    {
        $this->connection->client()->select($this->name);
        $this->connection->client()->uidStore(self::uids($numbers), '-FLAGS.SILENT', preg_split('/\s+/', trim($flag)));
        return true;
    }

    /**
     * UID SEARCH with the ddeboer condition string. Without SORT support the
     * sort criteria are approximated by UID order (= arrival order).
     */
    public function getMessages(?ConditionInterface $search = null, ?int $sortCriteria = null, bool $descending = false, ?string $charset = null): MessageIteratorInterface
    {
        $client = $this->connection->client();
        $client->select($this->name);
        $uids = $client->uidSearch($search ? $search->toString() : 'ALL');
        if ($descending) {
            $uids = array_reverse($uids);
        }
        return new SocketMessageIterator($this, $uids);
    }

    /** UID range such as "120:*" ("n:*" also returns the highest UID when it is below n). */
    public function getMessageSequence(string $sequence): MessageIteratorInterface
    {
        $client = $this->connection->client();
        $client->select($this->name);
        return new SocketMessageIterator($this, $client->uidSearch('UID ' . ImapClient::uidSet($sequence)));
    }

    public function getMessage(int $number): MessageInterface
    {
        return new SocketMessage($this, $number);
    }

    public function getIterator(): MessageIteratorInterface
    {
        return $this->getMessages();
    }

    public function addMessage(string $message, ?string $options = null, ?\DateTimeInterface $internalDate = null): bool
    {
        $flags = $options !== null && trim($options) !== '' ? preg_split('/\s+/', trim($options, " ()")) : [];
        $this->connection->client()->append($this->name, $message, $flags, $internalDate);
        return true;
    }

    public function getThread(): array
    {
        return [];
    }

    public function move($numbers, MailboxInterface $mailbox): void
    {
        $this->connection->moveUids($this->name, self::uids($numbers), $mailbox->getName());
    }

    public function copy($numbers, MailboxInterface $mailbox): void
    {
        $this->connection->copyUids($this->name, self::uids($numbers), $mailbox->getName());
    }

    public function count(): int
    {
        return (int)($this->connection->client()->status($this->name, ['MESSAGES'])['messages'] ?? 0);
    }

    /** @return int[] */
    private static function uids($numbers): array
    {
        if (is_int($numbers)) {
            return [$numbers];
        }
        if (is_string($numbers)) {
            $numbers = preg_split('/\s*,\s*/', trim($numbers));
        }
        $out = [];
        foreach ((array)$numbers as $n) {
            if (is_int($n) || ctype_digit((string)$n)) {
                $out[] = (int)$n;
            } else {
                throw new \InvalidArgumentException('Only plain UID lists are supported, got ' . $n);
            }
        }
        return $out;
    }
}
