<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\QuarantinePurge;
use AntispamBundle\Services\QuarantineService;
use Doctrine\ORM\EntityManagerInterface;

/**
 * "Usuń wszystkie wysokiego ryzyka" / "Usuń wszystko z kwarantanny" of one
 * mailbox (queued by QuarantinePurge): permanent deletion of what is in the
 * quarantine when the job runs - high risk re-evaluated now, never taken from
 * the page. IMAP: QuarantineService::purge(); SSH: agent 3.4 quarantine-purge.
 *
 * A job queued from the user area runs only while its requester still owns
 * the mailbox. The end (counts or error) is audited as quarantine.purge.
 */
class QuarantinePurgeHandler implements JobHandlerInterface
{
    public function __construct(
        private QuarantineService $quarantine,
        private EntityManagerInterface $em,
        private MailboxAccess $access,
    ) {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_QUARANTINE_PURGE;
    }

    public static function exclusive(): bool
    {
        return true;
    }

    public function handle(JobContext $context): array
    {
        $payload = $context->payload();
        $key = (string)($payload['key'] ?? '');
        $mode = (string)($payload['mode'] ?? '');
        $source = (string)($payload['source'] ?? QuarantinePurge::SOURCE_PANEL);
        $minScore = isset($payload['min_score']) ? (int)$payload['min_score'] : null;
        if ($key === '' || !QuarantinePurge::isMode($mode) || ($mode === QuarantineService::PURGE_MIN_SCORE && (int)$minScore < 1)) {
            throw new \RuntimeException('Nieprawidłowe zadanie (skrzynka / tryb).');
        }

        try {
            if ($context->requestedByType() === AuditLog::ACTOR_USER) {
                // Access may have been taken away since the click.
                $user = $this->em->getRepository(User::class)->findOneBy(['username' => (string)$context->requestedBy()]);
                if (!$user || !$this->access->canAccessMailboxKey($user, $key)) {
                    throw new \RuntimeException('Brak dostępu do tej skrzynki.');
                }
            }
            $context->progress(match ($mode) {
                QuarantineService::PURGE_ALL => 'Usuwanie wszystkich wiadomości z kwarantanny...',
                QuarantineService::PURGE_MIN_SCORE => sprintf('Sprawdzanie i usuwanie wiadomości z wynikiem od %d pkt z kwarantanny...', $minScore),
                default => 'Sprawdzanie i usuwanie wiadomości wysokiego ryzyka z kwarantanny...',
            });
            $result = $this->quarantine->purge($key, $mode, function (int $done, int $total) use ($context) {
                $context->progress(sprintf('Usunięto %d z %d', $done, $total), $done, $total);
            }, $minScore);
        } catch (\Throwable $e) {
            $this->audit($context, $key, $mode, $source, null, $e->getMessage());
            throw $e;
        }

        $this->audit($context, $key, $mode, $source, $result, null);
        $context->progress('Zakończone', (int)$result['deleted'], (int)$result['deleted']);
        return $result + ['key' => $key, 'mode' => $mode, 'source' => $source, 'shown' => $payload['shown'] ?? null, 'min_score' => $minScore];
    }

    private function audit(JobContext $context, string $key, string $mode, string $source, ?array $result, ?string $error): void
    {
        $details = ['ok' => $error === null, 'mode' => $mode, 'source' => $source] + (isset($context->payload()['min_score']) ? ['min_score' => (int)$context->payload()['min_score']] : []);
        foreach (['total', 'deleted', 'skipped', 'failed'] as $k) {
            $details[$k] = (int)($result[$k] ?? 0);
        }
        if ($error !== null) {
            $details['error'] = mb_substr($error, 0, 300);
        }
        $context->audit('quarantine.purge', targetType: 'quarantine', targetId: $key, label: $context->mailbox(), mailbox: $context->mailbox(), details: $details);
    }
}
