<?php

namespace AntispamBundle\Tests\Services\Jobs;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\TestCase;

/** Queue: dedupe, cancel, per-account view, stats for the health checks, purge. */
class JobQueueTest extends TestCase
{
    private JobsDatabase $db;

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
    }

    private function account(string $email = 'jan@firma.pl'): Account
    {
        $a = (new Account())->setName('Jan')->setEmail($email)->setConnectionType(Account::CONNECTION_IMAP);
        $this->db->em->persist($a);
        $this->db->em->flush();
        return $a;
    }

    public function testEnqueueStoresTheJobAndTheRequester()
    {
        $account = $this->account();
        $r = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, ['x' => 1], $account, 'Skanowanie: Jan', 'scan:1', requestedBy: 'admin', requestedByType: 'env_admin');
        $this->assertTrue($r->created);

        $job = $this->db->queue->find($r->id);
        $this->assertSame(BackgroundJob::STATUS_QUEUED, $job->getStatus());
        $this->assertSame(['x' => 1], $job->getPayload());
        $this->assertSame($account->getId(), $job->getAccountId());
        $this->assertSame('jan@firma.pl', $job->getMailbox());
        $this->assertSame('admin', $job->getRequestedBy());
        $this->assertSame('Skanowanie: Jan', $job->getLabel());
        $this->assertTrue($job->isActive());
    }

    public function testSameDedupeKeyIsNotQueuedTwiceUntilTheJobEnds()
    {
        $first = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, dedupeKey: 'scan:1');
        $again = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, dedupeKey: 'scan:1');
        $other = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, dedupeKey: 'scan:2');
        $free = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC);

        $this->assertFalse($again->created);
        $this->assertSame([$first->id, 'queued'], [$again->id, $again->existingStatus]);
        $this->assertTrue($other->created);
        $this->assertTrue($free->created, 'no key = no dedupe');
        $this->assertSame($first->id, $this->db->queue->findActive('scan:1'));

        $this->db->queue->cancel($first->id);
        $this->assertNull($this->db->queue->findActive('scan:1'));
        $this->assertTrue($this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, dedupeKey: 'scan:1')->created, 'a finished job frees its key');
    }

    public function testCancelQueuedAtOnceRunningAtTheNextCheck()
    {
        $queued = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $running = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $this->db->update($running, ['status' => 'running']);
        $done = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $this->db->update($done, ['status' => 'done']);

        $this->assertSame('cancelled', $this->db->queue->cancel($queued));
        $this->assertSame('cancel_requested', $this->db->queue->cancel($running));
        $this->assertNull($this->db->queue->cancel($done));
        $this->assertSame('running', $this->db->row($running)['status']);
        $this->assertSame(1, (int)$this->db->row($running)['cancel_requested']);
    }

    public function testActiveJobsPerAccountAndScanAllSkipRule()
    {
        $jan = $this->account();
        $ola = $this->account('ola@firma.pl');
        $a = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, [], $jan)->id;
        $b = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SYNC, [], $jan)->id;
        $this->db->update($b, ['status' => 'running']);
        $c = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SCAN, [], $ola)->id;
        $this->db->update($c, ['status' => 'done']);

        $active = $this->db->queue->activeByAccount();
        $this->assertSame([$a, $b], array_column($active[$jan->getId()], 'id'));
        $this->assertArrayNotHasKey($ola->getId(), $active);

        $this->assertTrue($this->db->queue->hasActive(BackgroundJob::TYPE_ACCOUNT_SCAN, $jan->getId()));
        $this->assertFalse($this->db->queue->hasActive(BackgroundJob::TYPE_ACCOUNT_SCAN, $ola->getId()));
        // Queued for over an hour: no worker runs, the scheduled scan must not wait for it.
        $this->db->update($a, ['available_at' => (new \DateTime('-2 hours'))->format('Y-m-d H:i:s')]);
        $this->assertFalse($this->db->queue->hasActive(BackgroundJob::TYPE_ACCOUNT_SCAN, $jan->getId()));
    }

    public function testStatsSeeTheOldestDueJobAndRecentFailures()
    {
        $old = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $this->db->update($old, ['available_at' => (new \DateTime('-30 minutes'))->format('Y-m-d H:i:s')]);
        $later = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $this->db->update($later, ['available_at' => (new \DateTime('+10 minutes'))->format('Y-m-d H:i:s')]);
        $failed = $this->db->queue->enqueue(BackgroundJob::TYPE_DIGEST_SEND, label: 'Raport')->id;
        $this->db->update($failed, ['status' => 'failed', 'error' => 'SMTP down', 'finished_at' => (new \DateTime('-1 hour'))->format('Y-m-d H:i:s')]);

        $stats = $this->db->queue->stats();
        $this->assertSame(2, $stats['queued']);
        $this->assertEqualsWithDelta(time() - 1800, $stats['oldest_queued_at']->getTimestamp(), 5, 'a job waiting for later does not count as stuck');
        $this->assertSame(1, $stats['failed_24h']);
        $this->assertSame('SMTP down', $stats['last_failed']['error']);
    }

    public function testPurgeDeletesOnlyOldFinishedJobs()
    {
        $ids = [];
        foreach (['done', 'failed', 'cancelled', 'queued', 'running'] as $status) {
            $ids[$status] = $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
            $this->db->update($id, ['status' => $status, 'created_at' => (new \DateTime('-40 days'))->format('Y-m-d H:i:s')]);
        }
        $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC); // recent
        $before = new \DateTime('-30 days');

        $this->assertSame(3, $this->db->queue->countFinishedBefore($before));
        $this->assertSame(3, $this->db->queue->purgeFinishedBefore($before));
        $this->assertSame(3, (int)$this->db->em->getConnection()->fetchOne('SELECT COUNT(*) FROM antispam_job'));
        $this->assertNotEmpty($this->db->row($ids['running']), 'active jobs are never purged');
    }
}
