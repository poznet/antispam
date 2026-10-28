<?php

namespace AntispamBundle\Imap;

/** Result of one tagged IMAP command. */
final class ImapResponse
{
    /**
     * @param string   $status     OK, NO or BAD
     * @param string   $text       text after the status (may start with a [RESP-CODE])
     * @param string[] $untagged   untagged responses without the leading "* " (literals inline)
     * @param string[] $challenges server challenges ("+ ...") not answered with a prepared continuation
     */
    public function __construct(
        public readonly string $status,
        public readonly string $text,
        public readonly array $untagged = [],
        public readonly array $challenges = [],
    ) {
    }

    public function isOk(): bool
    {
        return $this->status === 'OK';
    }
}
