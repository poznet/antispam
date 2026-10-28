<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\Jobs\EnqueueResult;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Feedback after a controller queued a background job: a flash message and
 * the redirect to the job page (docs/jobs.md).
 */
trait JobQueueTrait
{
    protected function redirectToJob(EnqueueResult $queued, string $what): RedirectResponse
    {
        $this->flashQueued($queued, $what);
        return $this->redirectToRoute('antispam_job_show', ['id' => $queued->id]);
    }

    /** After a new blacklist rule: mail already in INBOX is checked by a background job. */
    protected function flashRetroactive(?EnqueueResult $queued): void
    {
        if ($queued !== null) {
            $this->addFlash('info', sprintf('Poczta, która już jest w skrzynce (ostatnie 30 dni), zostanie sprawdzona pod kątem nowej reguły w tle - zadanie #%d (Przegląd → Zadania w tle).', $queued->id));
        }
    }

    protected function flashQueued(EnqueueResult $queued, string $what, ?string $created = null): void
    {
        if ($queued->created) {
            $this->addFlash('success', $created ?? sprintf('%s: zadanie dodane do kolejki (#%d) - wykona się w tle, możesz zamknąć tę stronę.', $what, $queued->id));
        } else {
            $this->addFlash('info', sprintf('%s: to zadanie jest już %s (#%d) - nie dodano drugiego.', $what,
                $queued->existingStatus === BackgroundJob::STATUS_RUNNING ? 'w trakcie wykonywania' : 'w kolejce', $queued->id));
        }
    }
}
