<?php

namespace AntispamBundle\Services;

/**
 * Prometheus text exposition (format 0.0.4) for /metrics: health check
 * results plus activity counters of the last 24 hours.
 */
class HealthMetrics
{
    const STATUS_VALUES = [HealthService::OK => 0, HealthService::WARN => 1, HealthService::FAIL => 2];
    const OVERALL_VALUES = [HealthService::STATUS_OK => 0, HealthService::STATUS_DEGRADED => 1, HealthService::STATUS_FAIL => 2];

    public function __construct(private HealthDataSource $data)
    {
    }

    public function render(array $report): string
    {
        $out = [];
        $this->metric($out, 'antispam_health_status', 'gauge', 'Overall health: 0 ok, 1 degraded, 2 fail.', [[[], self::OVERALL_VALUES[$report['status']] ?? 2]]);

        $checks = [];
        $accountAges = [];
        $cronAges = [];
        foreach ($report['checks'] as $check) {
            if (isset(self::STATUS_VALUES[$check['status']])) {
                $checks[] = [['check' => $check['key'], 'group' => $check['group']], self::STATUS_VALUES[$check['status']]];
            }
            if ($check['group'] === 'accounts' && array_key_exists('last_scan_age_seconds', $check['details'])) {
                $accountAges[] = [['account' => $check['label'], 'type' => (string)($check['details']['type'] ?? '')], $check['details']['last_scan_age_seconds']];
            }
            if (str_starts_with($check['key'], 'cron:') && isset($check['details']['age_seconds'])) {
                $cronAges[] = [['command' => substr($check['key'], 5)], $check['details']['age_seconds']];
            }
            if ($check['key'] === 'jobs') {
                $jobs = $check['details'];
            }
            if ($check['key'] === 'db' && isset($check['details']['size_bytes'])) {
                $dbSize = $check['details']['size_bytes'];
            }
            if ($check['key'] === 'disk' && isset($check['details']['free_bytes'])) {
                $diskFree = $check['details']['free_bytes'];
            }
        }
        $this->metric($out, 'antispam_health_check_status', 'gauge', 'Health check result: 0 ok, 1 warn, 2 fail (skipped checks are omitted).', $checks);
        $this->metric($out, 'antispam_account_last_scan_age_seconds', 'gauge', 'Seconds since the last successful scan of the mailbox.', $accountAges);
        $this->metric($out, 'antispam_cron_last_run_age_seconds', 'gauge', 'Seconds since the last start of the periodic job.', $cronAges);

        try {
            $this->activity($out);
        } catch (\Throwable $e) {
            // Database down: the health metrics above still tell the story.
            $this->metric($out, 'antispam_metrics_activity_error', 'gauge', '1 when the 24h activity counters could not be read.', [[[], 1]]);
        }

        if (isset($jobs)) {
            $this->metric($out, 'antispam_jobs_queued', 'gauge', 'Background jobs waiting in the queue.', [[[], (int)($jobs['queued'] ?? 0)]]);
            $this->metric($out, 'antispam_jobs_running', 'gauge', 'Background jobs being run by a worker.', [[[], (int)($jobs['running'] ?? 0)]]);
            $this->metric($out, 'antispam_jobs_failed_24h', 'gauge', 'Background jobs that failed in the last 24 hours.', [[[], (int)($jobs['failed_24h'] ?? 0)]]);
            $this->metric($out, 'antispam_jobs_oldest_queued_age_seconds', 'gauge', 'Seconds the oldest due job has been waiting (0 = none).', [[[], (int)($jobs['oldest_queued_age_seconds'] ?? 0)]]);
        }
        if (isset($dbSize)) {
            $this->metric($out, 'antispam_database_size_bytes', 'gauge', 'Size of the application database.', [[[], $dbSize]]);
        }
        if (isset($diskFree)) {
            $this->metric($out, 'antispam_disk_free_bytes', 'gauge', 'Free space on the filesystem holding var/.', [[[], $diskFree]]);
        }

        return implode("\n", $out) . "\n";
    }

    private function activity(array &$out): void
    {
        $since = new \DateTimeImmutable('-24 hours');
        $cron = $this->data->cronStatsSince($since);
        $runs = $failures = [];
        foreach ($cron as $command => $stats) {
            $runs[] = [['command' => $command], $stats['runs']];
            $failures[] = [['command' => $command], $stats['failures']];
        }
        $this->metric($out, 'antispam_scans_24h', 'gauge', 'Runs of the scan job (antispam:agent:scan-all) in the last 24 hours.', [[[], $cron['antispam:agent:scan-all']['runs'] ?? 0]]);
        $this->metric($out, 'antispam_cron_runs_24h', 'gauge', 'Cron log runs per command in the last 24 hours.', $runs);
        $this->metric($out, 'antispam_cron_failures_24h', 'gauge', 'Cron log runs that ended with a non-zero exit code in the last 24 hours.', $failures);

        $decisions = [];
        foreach ($this->data->decisionsSince($since) as $decision => $count) {
            $decisions[] = [['decision' => $decision], $count];
        }
        $this->metric($out, 'antispam_decisions_24h', 'gauge', 'Score log decisions in the last 24 hours (initial scans excluded).', $decisions);

        $quarantined = [];
        foreach ($this->data->quarantinedSince($since) as $account => $count) {
            $quarantined[] = [['account' => $account], $count];
        }
        $this->metric($out, 'antispam_quarantined_24h', 'gauge', 'Messages moved to quarantine in the last 24 hours, per mailbox.', $quarantined);
    }

    /** @param array<int, array{0: array<string,string>, 1: int|float}> $samples */
    private function metric(array &$out, string $name, string $type, string $help, array $samples): void
    {
        $out[] = '# HELP ' . $name . ' ' . $help;
        $out[] = '# TYPE ' . $name . ' ' . $type;
        foreach ($samples as [$labels, $value]) {
            $pairs = [];
            foreach ($labels as $k => $v) {
                $pairs[] = $k . '="' . self::escape((string)$v) . '"';
            }
            $out[] = $name . ($pairs ? '{' . implode(',', $pairs) . '}' : '') . ' ' . (is_float($value) ? $value : (int)$value);
        }
    }

    public static function escape(string $v): string
    {
        return str_replace(['\\', '"', "\n"], ['\\\\', '\\"', '\\n'], $v);
    }
}
