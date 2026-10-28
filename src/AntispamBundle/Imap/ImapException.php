<?php

namespace AntispamBundle\Imap;

/**
 * Error of the socket IMAP client (connection, protocol, NO / BAD answers).
 * Messages are shown in the panel, so they never contain tokens.
 */
class ImapException extends \RuntimeException
{
}
