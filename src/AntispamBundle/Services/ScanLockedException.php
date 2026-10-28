<?php

namespace AntispamBundle\Services;

/**
 * The mailbox is being scanned by another process right now (the scheduled
 * `antispam:agent:scan-all`, a background job, the SSH agent's own lock).
 * Not an error of the mailbox: the caller skips it or tries again later.
 */
class ScanLockedException extends \RuntimeException
{
    public function __construct(string $message = 'Skanowanie tej skrzynki już trwa w innym procesie - pominięto.', ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
