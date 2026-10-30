<?php

namespace AntispamBundle\Services\Jobs;

/**
 * The job the worker is running right now, so a long loop deep inside a
 * service (an IMAP scan / rescan batch of up to JOBS_BATCH_SECONDS) can stop
 * at the next message when "Anuluj" was clicked, instead of finishing the
 * batch. The database is asked at most every CHECK_SECONDS.
 *
 * Outside a job (web request, console command) nothing is ever requested.
 */
class JobCancellation
{
    const CHECK_SECONDS = 5;

    private ?JobContext $context = null;
    private float $lastCheck = 0.0;
    private bool $requested = false;

    public function begin(JobContext $context): void
    {
        $this->context = $context;
        $this->lastCheck = 0.0;
        $this->requested = false;
    }

    public function end(): void
    {
        $this->context = null;
        $this->requested = false;
    }

    public function isRequested(): bool
    {
        if ($this->context === null || $this->requested) {
            return $this->requested;
        }
        $now = microtime(true);
        if ($now - $this->lastCheck < self::CHECK_SECONDS) {
            return false;
        }
        $this->lastCheck = $now;
        try {
            $this->requested = $this->context->isCancelRequested();
        } catch (\Throwable) {
            // A database hiccup must not break the scan: the batch ends at its deadline anyway.
        }
        return $this->requested;
    }
}
