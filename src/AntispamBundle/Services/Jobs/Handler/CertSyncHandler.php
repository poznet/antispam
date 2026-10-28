<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;

/** "Synchronizuj teraz" on Lista CERT: download and replace the CERT Polska domain list. */
class CertSyncHandler implements JobHandlerInterface
{
    public function __construct(private CertHoleService $cert)
    {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_CERT_SYNC;
    }

    public static function exclusive(): bool
    {
        return true;
    }

    public function handle(JobContext $context): array
    {
        $context->progress('Pobieranie listy CERT Polska...');
        $result = $this->cert->sync();
        $context->audit('cert.sync', targetType: 'cert', label: mb_substr((string)$result['message'], 0, 200), details: ['ok' => (bool)$result['ok']]);
        if (!$result['ok']) {
            throw new \RuntimeException('Synchronizacja nieudana: ' . $result['message']);
        }
        return ['ok' => true, 'message' => (string)$result['message']];
    }
}
