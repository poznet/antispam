<?php

namespace AntispamBundle\Services\Jobs;

/** Outcome of JobQueue::enqueue(): the job id and whether it is new or an already active duplicate. */
final class EnqueueResult
{
    public function __construct(
        public readonly int $id,
        public readonly bool $created,
        /** Status of the existing job when $created is false (queued / running). */
        public readonly ?string $existingStatus = null,
    ) {
    }
}
