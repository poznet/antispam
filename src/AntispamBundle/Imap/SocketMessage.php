<?php

namespace AntispamBundle\Imap;

use AntispamBundle\Services\RawMessageParser;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\Message\EmailAddress;
use Ddeboer\Imap\Message\EmbeddedMessageInterface;
use Ddeboer\Imap\Message\Headers;
use Ddeboer\Imap\Message\Parameters;
use Ddeboer\Imap\MessageInterface;

/**
 * ddeboer MessageInterface for one message (by UID) of a SocketMailbox.
 *
 * Loaded lazily and never marks the message as seen (BODY.PEEK): the
 * header block, flags, INTERNALDATE and size on first header access, the
 * full source only when the body or attachments are needed. The MIME
 * body is decoded by RawMessageParser (same parser as the plugin check).
 *
 * Differences from ddeboer's ext-imap Message: getParts() is empty, the
 * message itself is not a navigable MIME tree (getStructure() is a stub),
 * attachments are SocketAttachment objects (filename, decoded content).
 */
final class SocketMessage implements MessageInterface
{
    /** Largest message source fetched for body / attachment checks. */
    public const MAX_SOURCE_BYTES = 50 * 1024 * 1024;

    private ?string $rawHeaders = null;
    private ?array $flags = null;
    private ?string $internalDate = null;
    private ?int $size = null;
    private ?Headers $headers = null;
    private ?string $source = null;
    private ?array $parts = null;
    private bool $deleted = false;

    public function __construct(private SocketMailbox $mailbox, private int $uid)
    {
    }

    // ---- loading ----------------------------------------------------------------

    private function loadHeader(): void
    {
        if ($this->rawHeaders !== null) {
            return;
        }
        $client = $this->mailbox->connection()->client();
        $client->select($this->mailbox->getName());
        $data = $client->uidFetch([$this->uid], 'UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER]')[$this->uid] ?? null;
        if ($data === null) {
            throw new ImapException(sprintf('Wiadomość UID %d nie istnieje w folderze %s', $this->uid, $this->mailbox->getName()));
        }
        $this->rawHeaders = (string)($data['BODY[HEADER]'] ?? '');
        $this->flags = array_map('strval', is_array($data['FLAGS'] ?? null) ? $data['FLAGS'] : []);
        $this->internalDate = isset($data['INTERNALDATE']) ? (string)$data['INTERNALDATE'] : null;
        $this->size = isset($data['RFC822.SIZE']) ? (int)$data['RFC822.SIZE'] : null;
    }

    private function loadSource(): string
    {
        if ($this->source !== null) {
            return $this->source;
        }
        $this->loadHeader();
        if ($this->size !== null && $this->size > self::MAX_SOURCE_BYTES) {
            throw new ImapException(sprintf('Wiadomość UID %d jest za duża do sprawdzenia (%d B)', $this->uid, $this->size));
        }
        $client = $this->mailbox->connection()->client();
        $client->select($this->mailbox->getName());
        $data = $client->uidFetch([$this->uid], 'UID BODY.PEEK[]')[$this->uid] ?? null;
        if ($data === null) {
            throw new ImapException(sprintf('Wiadomość UID %d nie istnieje w folderze %s', $this->uid, $this->mailbox->getName()));
        }
        return $this->source = (string)($data['BODY[]'] ?? '');
    }

    /** @return array{text:string, html:string, attachments:array} */
    private function parts(): array
    {
        if ($this->parts === null) {
            $this->parts = (new RawMessageParser($this->loadSource()))->getParts();
        }
        return $this->parts;
    }

    // ---- headers ------------------------------------------------------------------

    public function getRawHeaders(): string
    {
        $this->loadHeader();
        return $this->rawHeaders;
    }

    public function getRawMessage(): string
    {
        return $this->loadSource();
    }

    public function saveRawMessage($file): void
    {
        if (is_resource($file)) {
            fwrite($file, $this->loadSource());
            return;
        }
        file_put_contents((string)$file, $this->loadSource());
    }

    /** Same keys as ext-imap's imap_headerinfo() (+ maildate = INTERNALDATE, size). */
    public function getHeaders(): Headers
    {
        if ($this->headers !== null) {
            return $this->headers;
        }
        $this->loadHeader();
        $p = new RawMessageParser($this->rawHeaders . "\r\n\r\n");
        $raw = static fn (string $name) => ($v = $p->getHeaders($name)) ? trim(preg_replace('/\s+/', ' ', $v[0])) : null;

        $h = new \stdClass();
        foreach (['from' => 'from', 'to' => 'to', 'cc' => 'cc', 'bcc' => 'bcc', 'reply_to' => 'reply-to', 'sender' => 'sender', 'return_path' => 'return-path'] as $key => $name) {
            $value = $raw($name);
            if ($value !== null && $value !== '') {
                $list = self::parseAddresses($value);
                if ($list) {
                    $h->$key = $list;
                }
            }
        }
        foreach (['subject' => 'subject', 'date' => 'date', 'message_id' => 'message-id', 'in_reply_to' => 'in-reply-to', 'references' => 'references'] as $key => $name) {
            $value = $raw($name);
            if ($value !== null) {
                $h->$key = $value;
            }
        }
        if ($this->internalDate !== null) {
            $h->maildate = $this->internalDate;
        }
        if ($this->size !== null) {
            $h->size = $this->size;
        }
        $h->msgno = (string)$this->uid;

        return $this->headers = new Headers($h);
    }

    public function getId(): ?string
    {
        $id = $this->getHeaders()->get('message_id');
        return is_string($id) ? $id : null;
    }

    public function getFrom(): ?EmailAddress
    {
        $list = $this->addresses('from');
        return $list[0] ?? null;
    }

    public function getTo(): array
    {
        return $this->addresses('to');
    }

    public function getCc(): array
    {
        return $this->addresses('cc');
    }

    public function getBcc(): array
    {
        return $this->addresses('bcc');
    }

    public function getReplyTo(): array
    {
        return $this->addresses('reply_to');
    }

    public function getSender(): array
    {
        return $this->addresses('sender');
    }

    public function getReturnPath(): array
    {
        return $this->addresses('return_path');
    }

    public function getDate(): ?\DateTimeImmutable
    {
        $date = $this->getHeaders()->get('date');
        if (!is_string($date) || trim($date) === '') {
            return null;
        }
        $clean = trim((string)preg_replace('/\([^)]*\)/', '', $date));
        try {
            return new \DateTimeImmutable($clean);
        } catch (\Throwable) {
            $ts = strtotime($clean);
            return $ts !== false ? (new \DateTimeImmutable())->setTimestamp($ts) : null;
        }
    }

    public function getSize()
    {
        $this->loadHeader();
        return $this->size;
    }

    public function getSubject(): ?string
    {
        $subject = $this->getHeaders()->get('subject');
        return is_string($subject) ? $subject : null;
    }

    public function getInReplyTo(): array
    {
        $v = $this->getHeaders()->get('in_reply_to');
        return is_string($v) && $v !== '' ? explode(' ', $v) : [];
    }

    public function getReferences(): array
    {
        $v = $this->getHeaders()->get('references');
        return is_string($v) && $v !== '' ? explode(' ', $v) : [];
    }

    // ---- body -----------------------------------------------------------------------

    public function getAllContentsBySubtype(string $subtype): array
    {
        $key = strtoupper($subtype) === 'HTML' ? 'html' : (strtoupper($subtype) === 'PLAIN' ? 'text' : null);
        $value = $key ? $this->parts()[$key] : '';
        return $value !== '' ? [$value] : [];
    }

    public function getBodyHtml(): ?string
    {
        $html = $this->parts()['html'];
        return $html !== '' ? $html : null;
    }

    public function getBodyHtmlParts(): array
    {
        return $this->getAllContentsBySubtype('HTML');
    }

    public function getCompleteBodyHtml(): ?string
    {
        return $this->getBodyHtml();
    }

    public function getBodyText(): ?string
    {
        $text = $this->parts()['text'];
        return $text !== '' ? $text : null;
    }

    public function getCompleteBodyText(): ?string
    {
        return $this->getBodyText();
    }

    /** @return SocketAttachment[] */
    public function getAttachments(): array
    {
        $out = [];
        foreach ($this->parts()['attachments'] as $a) {
            $out[] = new SocketAttachment((string)$a['filename'], (string)$a['type'], (string)$a['data']);
        }
        return $out;
    }

    public function hasAttachments(): bool
    {
        return $this->getAttachments() !== [];
    }

    public function getContent(): string
    {
        $source = $this->loadSource();
        $pos = strpos($source, "\r\n\r\n");
        return $pos === false ? '' : (string)substr($source, $pos + 4);
    }

    public function getDecodedContent(): string
    {
        return (string)($this->getBodyText() ?? $this->getBodyHtml() ?? '');
    }

    // ---- flags / actions ----------------------------------------------------------------

    public function isRecent(): ?string
    {
        return $this->hasFlag('\\Recent') ? 'R' : null;
    }

    public function isUnseen(): bool
    {
        return !$this->hasFlag('\\Seen');
    }

    public function isFlagged(): bool
    {
        return $this->hasFlag('\\Flagged');
    }

    public function isAnswered(): bool
    {
        return $this->hasFlag('\\Answered');
    }

    public function isDeleted(): bool
    {
        return $this->deleted || $this->hasFlag('\\Deleted');
    }

    public function isDraft(): bool
    {
        return $this->hasFlag('\\Draft');
    }

    public function isSeen(): bool
    {
        return $this->hasFlag('\\Seen');
    }

    public function maskAsSeen(): bool
    {
        return $this->markAsSeen();
    }

    public function markAsSeen(): bool
    {
        return $this->setFlag('\\Seen');
    }

    public function copy(MailboxInterface $mailbox): void
    {
        $this->mailbox->connection()->copyUids($this->mailbox->getName(), [$this->uid], $mailbox->getName());
    }

    public function move(MailboxInterface $mailbox): void
    {
        $this->mailbox->connection()->moveUids($this->mailbox->getName(), [$this->uid], $mailbox->getName());
        $this->deleted = true;
    }

    public function delete(): void
    {
        $this->mailbox->connection()->flagDeleted($this->mailbox->getName(), [$this->uid]);
        $this->deleted = true;
    }

    public function undelete(): void
    {
        $this->mailbox->connection()->unflagDeleted($this->mailbox->getName(), [$this->uid]);
        $this->deleted = false;
    }

    public function setFlag(string $flag): bool
    {
        $this->mailbox->setFlag($flag, [$this->uid]);
        $this->flags = null === $this->flags ? null : array_values(array_unique(array_merge($this->flags, preg_split('/\s+/', trim($flag)))));
        return true;
    }

    public function clearFlag(string $flag): bool
    {
        $this->mailbox->clearFlag($flag, [$this->uid]);
        $this->flags = null === $this->flags ? null : array_values(array_diff($this->flags, preg_split('/\s+/', trim($flag))));
        return true;
    }

    // ---- PartInterface (the message as a single leaf) --------------------------------------

    public function getNumber(): int
    {
        return $this->uid;
    }

    public function getCharset(): ?string
    {
        return null;
    }

    public function getType(): ?string
    {
        return null;
    }

    public function getSubtype(): ?string
    {
        return null;
    }

    public function getEncoding(): ?string
    {
        return null;
    }

    public function getDisposition(): ?string
    {
        return null;
    }

    public function getDescription(): ?string
    {
        return null;
    }

    public function getBytes()
    {
        return $this->getSize();
    }

    public function getLines(): ?string
    {
        return null;
    }

    public function getParameters(): Parameters
    {
        return new Parameters();
    }

    public function getStructure(): \stdClass
    {
        return new \stdClass();
    }

    public function getPartNumber(): string
    {
        return '';
    }

    public function getParts(): array
    {
        return [];
    }

    public function getEmbeddedMessage(): EmbeddedMessageInterface
    {
        throw new \LogicException('Not an embedded message');
    }

    public function current(): mixed
    {
        return null;
    }

    public function key(): mixed
    {
        return null;
    }

    public function next(): void
    {
    }

    public function rewind(): void
    {
    }

    public function valid(): bool
    {
        return false;
    }

    public function hasChildren(): bool
    {
        return false;
    }

    public function getChildren(): ?\RecursiveIterator
    {
        return null;
    }

    // ---- helpers --------------------------------------------------------------------------

    private function hasFlag(string $flag): bool
    {
        if ($this->flags === null) {
            $this->rawHeaders = null;
            $this->loadHeader();
        }
        foreach ($this->flags as $f) {
            if (strcasecmp($f, $flag) === 0) {
                return true;
            }
        }
        return false;
    }

    /** @return EmailAddress[] */
    private function addresses(string $key): array
    {
        $list = $this->getHeaders()->get($key);
        $out = [];
        foreach (is_array($list) ? $list : [] as $a) {
            if (!isset($a->mailbox) || $a->mailbox === '') {
                continue;
            }
            $out[] = new EmailAddress((string)$a->mailbox, isset($a->host) && $a->host !== '' ? (string)$a->host : null, isset($a->personal) && $a->personal !== '' ? (string)$a->personal : null);
        }
        return $out;
    }

    /**
     * Address list -> [{mailbox, host, personal}] like imap_headerinfo().
     * The display name stays MIME-encoded: Headers decodes it.
     *
     * @return \stdClass[]
     */
    public static function parseAddresses(string $value): array
    {
        $out = [];
        if (\function_exists('imap_rfc822_parse_adrlist')) {
            $parsed = @imap_rfc822_parse_adrlist($value, '');
            @imap_errors();
            foreach (is_array($parsed) ? $parsed : [] as $a) {
                if (!isset($a->mailbox) || $a->mailbox === '' || ($a->host ?? '') === '.SYNTAX-ERROR.') {
                    continue;
                }
                $item = new \stdClass();
                $item->mailbox = (string)$a->mailbox;
                $item->host = isset($a->host) && $a->host !== '' ? (string)$a->host : null;
                if (isset($a->personal) && $a->personal !== '') {
                    $item->personal = (string)$a->personal;
                }
                $out[] = $item;
            }
            if ($out) {
                return $out;
            }
        }
        // Fallback (no ext-imap or unparsable list): addresses in <...> or bare.
        if (preg_match_all('/<([^<>@\s]+)@([^<>\s]+)>|(?<![<\w.+-])([\w.+\-=]+)@([\w.\-]+\w)/', $value, $m, PREG_SET_ORDER)) {
            foreach ($m as $hit) {
                $item = new \stdClass();
                $item->mailbox = $hit[1] !== '' ? $hit[1] : $hit[3];
                $item->host = $hit[1] !== '' ? $hit[2] : $hit[4];
                $out[] = $item;
            }
        }
        return $out;
    }
}
