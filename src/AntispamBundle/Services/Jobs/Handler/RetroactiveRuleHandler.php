<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\RetroactiveSpamService;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * A new blacklist rule applied to mail already in INBOX
 * (RetroactiveSpamService::applyRule - IMAP / SSH logins and moving mail).
 * Queued through DeferredRetroactivePass by the panel rule forms, the
 * phishing page and plugin reports.
 */
class RetroactiveRuleHandler implements JobHandlerInterface
{
    const RULE_CLASSES = ['blacklist' => Blacklist::class, 'email_blacklist' => EmailBlacklist::class];

    public function __construct(
        private EntityManagerInterface $em,
        private RetroactiveSpamService $retroactive,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_RULE_RETROACTIVE;
    }

    public static function exclusive(): bool
    {
        return true;
    }

    public function handle(JobContext $context): array
    {
        $payload = $context->payload();
        $class = self::RULE_CLASSES[$payload['rule'] ?? ''] ?? null;
        $rule = $class ? $this->em->find($class, (int)($payload['id'] ?? 0)) : null;
        if (!$rule) {
            return ['moved' => 0, 'errors' => [], 'skipped' => null, 'summary' => 'Reguła została usunięta, zanim sprawdzono skrzynki - nic nie przeniesiono.'];
        }

        $context->progress('Sprawdzanie poczty w skrzynkach (ostatnie ' . RetroactiveSpamService::DAYS . ' dni)...');
        $result = $this->retroactive->applyRule($rule);
        $result['summary'] = RetroactiveSpamService::describe($result) ?? 'Żadna wiadomość w skrzynce nie pasowała do reguły.';
        $this->logger?->info('antispam: retroactive pass of a new rule', [
            'job' => $context->jobId(), 'owner' => $rule->getEmail(),
            'moved' => $result['moved'], 'errors' => $result['errors'], 'skipped' => $result['skipped'],
        ]);
        return $result;
    }
}
