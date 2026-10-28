<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\Jobs\JobQueue;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * "Zadania w tle": the background job queue (docs/jobs.md) - list, one job's
 * status / progress / result, a JSON status for the page's auto-refresh and
 * cancelling. Administrators only (no user-area action opens a job page).
 */
#[Route('/jobs')]
#[IsGranted('ROLE_ADMIN')]
class JobController extends AbstractController
{
    use AuditTrait;

    public function __construct(
        private EntityManagerInterface $em,
        private JobQueue $queue,
    ) {
    }

    #[Route('/', name: 'antispam_job_index', methods: ['GET'])]
    #[Template('@Antispam/Job/index.html.twig')]
    public function indexAction(Request $request)
    {
        $status = (string)$request->query->get('status', '');
        $status = $status === 'active' || array_key_exists($status, BackgroundJob::STATUSES) ? $status : null;
        $type = (string)$request->query->get('type', '');
        $type = array_key_exists($type, BackgroundJob::TYPES) ? $type : null;

        return [
            'jobs' => $this->em->getRepository(BackgroundJob::class)->findRecent(200, $status, $type),
            'status' => $status,
            'type' => $type,
            'statuses' => BackgroundJob::STATUSES,
            'types' => BackgroundJob::TYPES,
            'stats' => $this->queue->stats(),
            'stuck_minutes' => JobQueue::STUCK_WARN_MINUTES,
            'retention' => BackgroundJob::DEFAULT_RETENTION_DAYS,
        ];
    }

    #[Route('/{id}', name: 'antispam_job_show', requirements: ['id' => '\d+'], methods: ['GET'])]
    #[Template('@Antispam/Job/show.html.twig')]
    public function showAction(int $id)
    {
        $job = $this->job($id);
        $account = $job->getAccountId() !== null ? $this->em->find(Account::class, $job->getAccountId()) : null;

        return [
            'job' => $job,
            'account' => $account,
            'result' => $job->getResult(),
            'stats' => $this->queue->stats(),
            'stuck_minutes' => JobQueue::STUCK_WARN_MINUTES,
        ];
    }

    /** Polled by jobs-status.js while the job is queued / running. */
    #[Route('/{id}/status', name: 'antispam_job_status', requirements: ['id' => '\d+'], methods: ['GET'])]
    public function statusAction(int $id): JsonResponse
    {
        $job = $this->job($id);
        $response = new JsonResponse(self::statusData($job));
        $response->headers->set('Cache-Control', 'no-store');
        return $response;
    }

    #[Route('/{id}/cancel', name: 'antispam_job_cancel', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function cancelAction(int $id, Request $request)
    {
        if (!$this->isCsrfTokenValid('job_cancel_' . $id, (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
        $job = $this->job($id);
        $state = $this->queue->cancel($id);
        if ($state === BackgroundJob::STATUS_CANCELLED) {
            $this->addFlash('success', 'Zadanie anulowane.');
        } elseif ($state !== null) {
            $this->addFlash('info', 'Zadanie zostanie przerwane przy najbliższej okazji (skan - po bieżącej partii; pojedyncze polecenie dokończy się).');
        } else {
            $this->addFlash('warning', 'Zadanie już się zakończyło.');
        }
        if ($state !== null) {
            $this->audit('job.cancel', targetType: 'job', targetId: $id, label: $job->getLabel(), mailbox: $job->getMailbox(), details: ['type' => $job->getType(), 'state' => $state]);
        }
        return $this->redirectToRoute('antispam_job_show', ['id' => $id]);
    }

    public static function statusData(BackgroundJob $job): array
    {
        return [
            'id' => $job->getId(),
            'status' => $job->getStatus(),
            'status_label' => $job->getStatusLabel(),
            'finished' => $job->isFinished(),
            'progress' => $job->getProgress(),
            'done' => $job->getProgressDone(),
            'total' => $job->getProgressTotal(),
            'percent' => $job->getPercent(),
            'duration' => $job->getDuration(),
            'cancel_requested' => $job->isCancelRequested(),
        ];
    }

    private function job(int $id): BackgroundJob
    {
        $job = $this->queue->find($id);
        if (!$job) {
            throw $this->createNotFoundException('Nie ma takiego zadania.');
        }
        return $job;
    }
}
