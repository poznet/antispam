<?php

namespace AntispamBundle\Services\Jobs\Handler;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\PhishingReport;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\PhishingForwardService;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Forwarding of the phishing reports selected on the list (one e-mail per
 * report). Already forwarded messages (also copies reported by another
 * mailbox) and false positives are skipped - resending is only possible one
 * by one, with confirmation.
 */
class PhishingForwardHandler implements JobHandlerInterface
{
    public function __construct(
        private EntityManagerInterface $em,
        private PhishingForwardService $forwarder,
    ) {
    }

    public static function type(): string
    {
        return BackgroundJob::TYPE_PHISHING_FORWARD;
    }

    public static function exclusive(): bool
    {
        return false;
    }

    public function handle(JobContext $context): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', (array)($context->payload()['ids'] ?? [])))));
        $counts = ['sent' => 0, 'failed' => 0, 'skipped' => 0];
        $errors = [];
        $sent = [];
        foreach ($ids as $i => $id) {
            $context->progress(sprintf('Wysyłanie zgłoszeń: %d z %d', $i, count($ids)), $i, count($ids));
            $report = $this->em->getRepository(PhishingReport::class)->find($id);
            if (!$report) {
                continue;
            }
            if (isset($sent[$report->getSha256()])) {
                $counts['skipped']++;
                continue;
            }
            $result = $this->forwarder->forward($report);
            $context->audit('phishing.forward', targetType: 'phishing', targetId: $id, label: $report->getSender(), mailbox: $report->getAccountEmail(), details: ['status' => $result['status'], 'to' => $report->getForwardedTo(), 'bulk' => true, 'error' => $result['error'] ?? null]);
            $counts[$result['status']] = ($counts[$result['status']] ?? 0) + 1;
            if ($result['status'] === 'sent') {
                $sent[$report->getSha256()] = true;
            } elseif (!empty($result['error'])) {
                $errors[$result['error']] = '#' . $id . ': ' . $result['error'];
            }
        }
        $context->progress(sprintf('Wysłano zgłoszenia: %d z %d', count($ids), count($ids)), count($ids), count($ids));
        return ['counts' => $counts, 'errors' => array_values(array_slice($errors, 0, 20))];
    }
}
