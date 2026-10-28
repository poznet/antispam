<?php

namespace AntispamBundle\Tests\Services\Jobs;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\Jobs\JobContext;
use AntispamBundle\Services\Jobs\JobHandlerInterface;
use AntispamBundle\Services\Jobs\JobWorker;
use AntispamBundle\Tests\Support\JobsDatabase;
use PHPUnit\Framework\TestCase;

/** Exclusive test handler (type cert.sync) running a closure. */
class ExclusiveTestHandler implements JobHandlerInterface
{
    public function __construct(private \Closure $fn) {}
    public static function type(): string { return BackgroundJob::TYPE_CERT_SYNC; }
    public static function exclusive(): bool { return true; }
    public function handle(JobContext $context): array { return ($this->fn)($context); }
}

/** Non-exclusive test handler (type account.sync). */
class SharedTestHandler extends ExclusiveTestHandler
{
    public static function type(): string { return BackgroundJob::TYPE_ACCOUNT_SYNC; }
    public static function exclusive(): bool { return false; }
}

/** Worker: claim + result / error, resumable jobs, cancel, dedupe key while running, stale recovery. */
class JobWorkerTest extends TestCase
{
    private JobsDatabase $db;

    protected function setUp(): void
    {
        $this->db = new JobsDatabase();
    }

    private function worker(JobHandlerInterface ...$handlers): JobWorker
    {
        $w = $this->db->worker($handlers);
        $w->configure(0, 60);
        return $w;
    }

    public function testRunsTheJobAndStoresTheResult()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC, ['a' => 1], dedupeKey: 'cert')->id;
        $seen = null;
        $worker = $this->worker(new ExclusiveTestHandler(function (JobContext $c) use (&$seen) {
            $row = $this->db->row($c->jobId());
            $seen = [$c->payload(), $row['status'], $row['active_key'], $row['worker']];
            $c->progress('w połowie', 1, 2);
            return ['ok' => true];
        }));

        $this->assertSame(['id' => $id, 'status' => 'done'], $worker->runNext());
        $this->assertSame([['a' => 1], 'running', 'cert', $worker->getWorkerId()], $seen, 'an exclusive job keeps its key while running');
        $row = $this->db->row($id);
        $this->assertSame(['done', '{"ok":true}', null, 1, 'w połowie'], [$row['status'], $row['result'], $row['active_key'], (int)$row['attempts'], $row['progress']]);
        $this->assertNotNull($row['finished_at']);
        $this->assertNull($worker->runNext(), 'queue empty');
    }

    public function testExceptionFailsTheJobWithItsMessage()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC, dedupeKey: 'cert')->id;
        $worker = $this->worker(new ExclusiveTestHandler(fn() => throw new \RuntimeException('serwer nie odpowiada')));

        $this->assertSame('failed', $worker->runNext()['status']);
        $this->assertSame(['failed', 'serwer nie odpowiada', null], [$this->db->row($id)['status'], $this->db->row($id)['error'], $this->db->row($id)['active_key']]);
    }

    public function testUnknownTypeFails()
    {
        $id = $this->db->queue->enqueue('no.such.type')->id;
        $this->assertSame('failed', $this->worker()->runNext()['status']);
        $this->assertStringContainsString('Nieznany typ', $this->db->row($id)['error']);
    }

    public function testNonExclusiveJobReleasesItsKeyWhenItStarts()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SYNC, dedupeKey: 'sync:1')->id;
        $second = null;
        $worker = $this->worker(new SharedTestHandler(function () use (&$second) {
            $second = $this->db->queue->enqueue(BackgroundJob::TYPE_ACCOUNT_SYNC, dedupeKey: 'sync:1');
            return [];
        }));
        $worker->runNext();
        $this->assertTrue($second->created);
        $this->assertNotSame($id, $second->id);
    }

    public function testResumableJobRunsInSeveralRunsWithItsState()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC, dedupeKey: 'cert')->id;
        $worker = $this->worker(new ExclusiveTestHandler(function (JobContext $c) {
            $n = ($c->state()['n'] ?? 0) + 1;
            if ($n < 3) {
                $c->continueLater(['n' => $n], 0, 'partia ' . $n);
                return [];
            }
            return ['runs' => $n];
        }));

        $this->assertSame('queued', $worker->runNext()['status']);
        $row = $this->db->row($id);
        $this->assertSame(['queued', '{"n":1}', 'cert', 'partia 1'], [$row['status'], $row['state'], $row['active_key'], $row['progress']], 'the key stays taken between runs');
        $this->assertFalse($this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC, dedupeKey: 'cert')->created);

        $worker->runNext();
        $this->assertSame('done', $worker->runNext()['status']);
        $this->assertSame(['{"runs":3}', 3], [$this->db->row($id)['result'], (int)$this->db->row($id)['attempts']]);
    }

    public function testDelayedContinuationIsNotPickedUpEarly()
    {
        $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC);
        $worker = $this->worker(new ExclusiveTestHandler(function (JobContext $c) {
            $c->continueLater([], 300, 'czeka');
            return [];
        }));
        $worker->runNext();
        $this->assertNull($worker->runNext());
    }

    public function testCancelRequestedDuringARunStopsTheContinuation()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $worker = $this->worker(new ExclusiveTestHandler(function (JobContext $c) {
            $this->db->queue->cancel($c->jobId()); // admin presses "Anuluj" meanwhile
            $c->continueLater(['result' => ['checked' => 5]]);
            return [];
        }));
        $this->assertSame('cancelled', $worker->runNext()['status']);
        $this->assertSame('{"checked":5}', $this->db->row($id)['result'], 'the finished part is kept');
    }

    public function testCancelledBeforeStartIsNeverRun()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $this->db->update($id, ['cancel_requested' => 1]);
        $worker = $this->worker(new ExclusiveTestHandler(fn() => $this->fail('must not run')));
        $this->assertSame('cancelled', $worker->runNext()['status']);
    }

    public function testStaleRunningJobIsRequeuedThenFailedAfterRepeatedInterruptions()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC, dedupeKey: 'cert')->id;
        $worker = $this->db->worker([]);
        $worker->configure(60, 60, 600);
        $stale = (new \DateTime('-20 minutes'))->format('Y-m-d H:i:s');
        $this->db->update($id, ['status' => 'running', 'worker' => 'other-host:123', 'heartbeat_at' => $stale, 'started_at' => $stale]);

        $this->assertSame(1, $worker->recoverStale());
        $row = $this->db->row($id);
        $this->assertSame(['queued', null, 1, 'cert'], [$row['status'], $row['worker'], (int)$row['interruptions'], $row['active_key']]);

        for ($i = 2; $i <= JobWorker::MAX_INTERRUPTIONS; $i++) {
            $this->db->update($id, ['status' => 'running', 'worker' => 'other-host:123', 'heartbeat_at' => $stale]);
            $worker->recoverStale();
        }
        $row = $this->db->row($id);
        $this->assertSame(['failed', null], [$row['status'], $row['active_key']]);
        $this->assertStringContainsString('przerwany', $row['error']);
    }

    public function testLiveJobWithFreshHeartbeatIsLeftAlone()
    {
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $now = (new \DateTime())->format('Y-m-d H:i:s');
        $this->db->update($id, ['status' => 'running', 'worker' => 'other-host:123', 'heartbeat_at' => $now, 'started_at' => $now]);
        $worker = $this->db->worker([]);
        $worker->configure(60, 60, 600);
        $this->assertSame(0, $worker->recoverStale());
    }

    public function testJobOfADeadProcessOnThisHostIsRecoveredAtOnce()
    {
        if (!\function_exists('posix_kill')) {
            $this->markTestSkipped('posix extension missing');
        }
        $id = $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC)->id;
        $now = (new \DateTime())->format('Y-m-d H:i:s');
        // A pid far above any real one on this host.
        $this->db->update($id, ['status' => 'running', 'worker' => mb_substr((string)gethostname(), 0, 80) . ':4194000', 'heartbeat_at' => $now, 'started_at' => $now]);
        $worker = $this->db->worker([]);
        $worker->configure(3600, 60);
        $this->assertSame(1, $worker->recoverStale());
        $this->assertSame('queued', $this->db->row($id)['status']);
    }

    public function testWorkOnceDrainsTheQueueAndExits()
    {
        foreach ([1, 2, 3] as $i) {
            $this->db->queue->enqueue(BackgroundJob::TYPE_CERT_SYNC);
        }
        $worker = $this->worker(new ExclusiveTestHandler(fn() => []));
        $lines = [];
        $this->assertSame(3, $worker->work(0, 0, 1, true, function ($l) use (&$lines) { $lines[] = $l; }));
        $this->assertSame(0, (int)$this->db->em->getConnection()->fetchOne("SELECT COUNT(*) FROM antispam_job WHERE status <> 'done'"));
        $this->assertNotEmpty($lines);
    }
}
