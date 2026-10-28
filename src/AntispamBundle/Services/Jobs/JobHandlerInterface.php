<?php

namespace AntispamBundle\Services\Jobs;

use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

/**
 * Runs one type of background job (BackgroundJob::TYPE_*). Implementations are
 * collected by the `antispam.job_handler` tag (autoconfigured).
 *
 * handle() returns the result stored on the job (rendered by the job page
 * template Job/result/<type>.html.twig) or throws - the exception message
 * becomes the job's error. A long job reports progress through the context
 * and can split itself into several runs with JobContext::continueLater().
 */
#[AutoconfigureTag('antispam.job_handler')]
interface JobHandlerInterface
{
    /** BackgroundJob::TYPE_* this handler runs. */
    public static function type(): string;

    /**
     * true: the dedupe key stays taken while the job runs (a second scan of a
     * mailbox is refused until the first one ends); false: only while queued
     * (a rules sync requested during a running sync is queued again, because
     * the running one may have exported the rules before the change).
     */
    public static function exclusive(): bool;

    public function handle(JobContext $context): array;
}
