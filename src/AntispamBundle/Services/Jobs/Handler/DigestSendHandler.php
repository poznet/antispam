<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\QuarantineDigestService;

/**
 * "Wyślij teraz" on Raport kwarantanny: reads the quarantine of every mailbox
 * (IMAP / SSH) and sends the digests - every mailbox not switched off on its
 * own, whatever its send hour.
 */
class DigestSendHandler implements JobHandlerInterface
{
    public function __construct(private QuarantineDigestService $digest)
    {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_DIGEST_SEND;
    }

    public static function exclusive(): bool
    {
        return true;
    }

    public function handle(JobContext $context): array
    {
        if ($errors = $this->digest->configurationErrors()) {
            throw new \RuntimeException(implode(' ', $errors));
        }
        $context->progress('Odczyt kwarantann i wysyłka raportów...');
        $rows = [];
        foreach ($this->digest->sendAll(null, null, false, true, false, true) as $row) {
            $rows[] = [
                'key' => (string)$row['key'], 'recipient' => (string)$row['recipient'], 'count' => (int)$row['count'],
                'status' => (string)$row['status'], 'error' => !empty($row['error']) ? (string)$row['error'] : null,
            ];
        }
        return ['rows' => $rows];
    }
}
