<?php

namespace AntispamBundle\Imap;

use Ddeboer\Imap\MessageInterface;
use Ddeboer\Imap\MessageIteratorInterface;

/**
 * Like ddeboer's MessageIterator: holds UIDs (getArrayCopy() returns them),
 * current() builds the lazily loaded message.
 *
 * @extends \ArrayIterator<int, int>
 */
final class SocketMessageIterator extends \ArrayIterator implements MessageIteratorInterface
{
    /** @param int[] $uids */
    public function __construct(private SocketMailbox $mailbox, array $uids)
    {
        parent::__construct(array_values($uids));
    }

    public function current(): MessageInterface
    {
        $uid = parent::current();
        if (!is_int($uid)) {
            throw new \OutOfBoundsException('No current message');
        }
        return new SocketMessage($this->mailbox, $uid);
    }
}
