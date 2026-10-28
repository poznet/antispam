<?php

namespace AntispamBundle\Services;

use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\CronRun;
use AntispamBundle\Services\Jobs\JobQueue;

/**
 * Health checks of the whole installation, used by /health, /metrics, the
 * "Stan systemu" page and `antispam:health:check` (alerts). Reusable by other
 * tools (e.g. a doctor command): call run() and read the report.
 *
 * Report:
 *   status      ok | degraded | fail
 *   checked_at  ISO 8601
 *   full        bool - the slow checks (IMAP login, SSH agent, schema) ran
 *   checks      list of {key, group, label, status, message, critical, details}
 *
 * Check status: ok | warn | fail | skip (feature disabled / not applicable).
 * The overall status is "fail" only when a critical check (database,
 * scheduler) fails; any other failure or warning makes it "degraded", so one
 * mailbox with a changed password does not mark the whole service as down.
 */
class HealthService
{
    const OK = 'ok';
    const WARN = 'warn';
    const FAIL = 'fail';
    const SKIP = 'skip';

    const STATUS_OK = 'ok';
    const STATUS_DEGRADED = 'degraded';
    const STATUS_FAIL = 'fail';

    /**
     * Periodic jobs of docker/scheduler.sh with their default interval in
     * minutes. The real interval is inferred from the cron log (median gap of
     * the latest runs), so a changed SCAN_INTERVAL needs no extra setting.
     */
    const JOBS = [
        'antispam:agent:scan-all' => ['label' => 'Skanowanie skrzynek', 'interval' => 5],
        'antispam:health:check' => ['label' => 'Kontrola stanu i alerty', 'interval' => 15],
        'antispam:feed:sync' => ['label' => 'Synchronizacja wspólnej bazy spamu', 'interval' => 15],
        'antispam:cert:sync' => ['label' => 'Synchronizacja listy CERT', 'interval' => 360],
        'antispam:digest:send' => ['label' => 'Raport kwarantanny', 'interval' => 1440],
        'antispam:purge' => ['label' => 'Czyszczenie starych danych', 'interval' => 1440],
        'antispam:rescan:due' => ['label' => 'Cotygodniowy ponowny skan skrzynek (kolejkowanie)', 'interval' => 60],
    ];

    /** A run without an end after this long was killed (as on the cron log page). */
    const STALE_RUN_SECONDS = 7200;
    const CONSECUTIVE_JOB_FAILURES = 3;
    const CLAMAV_TIMEOUT = 3;
    const DISK_FAIL_BYTES = 500 * 1024 * 1024;
    const DISK_WARN_BYTES = 2 * 1024 * 1024 * 1024;
    const DISK_WARN_RATIO = 0.05;
    const CERT_WARN_HOURS = 18;
    const CERT_FAIL_HOURS = 72;
    const FEED_WARN_HOURS = 2;
    const FEED_FAIL_HOURS = 24;

    private ?\DateTimeImmutable $now = null;

    public function __construct(
        private HealthDataSource $data,
        private HealthSettings $settings,
        private ScoringService $scoring,
        private ClamavService $clamav,
        private CertHoleService $cert,
        private SpamSignalService $feed,
        private SshService $ssh,
        private ImapScanService $imap,
        private ?JobQueue $jobs = null,
    ) {
    }

    /** Fixes "now" (tests). */
    public function setNow(?\DateTimeImmutable $now): void
    {
        $this->now = $now;
    }

    /**
     * @param bool $full also log in to every IMAP account, query every SSH
     *                   agent and diff the schema (slow: seconds per account)
     */
    public function run(bool $full = false): array
    {
        $checks = [];
        $db = $this->guard('db', 'system', 'Baza danych', true, fn() => $this->checkDatabase());
        $checks[] = $db;
        if ($db['status'] !== self::FAIL) {
            $checks[] = $this->guard('scheduler', 'cron', 'Scheduler (cron)', true, fn() => $this->checkScheduler());
            foreach (self::JOBS as $command => $job) {
                $checks[] = $this->guard('cron:' . $command, 'cron', $job['label'], false, fn() => $this->checkJob($command, $job['interval']));
            }
            if ($this->jobs) {
                $checks[] = $this->guard('jobs', 'cron', 'Kolejka zadań w tle', false, fn() => $this->checkJobQueue());
            }
            $accounts = [];
            try {
                $accounts = $this->data->accounts();
            } catch (\Throwable $e) {
                $checks[] = self::check('accounts', 'accounts', 'Konta pocztowe', self::FAIL, 'Nie udało się odczytać kont: ' . $e->getMessage());
            }
            foreach ($accounts as $account) {
                $checks[] = $this->guard('account:' . $account->getId(), 'accounts', $account->getEmail(), false, fn() => $this->checkAccount($account, $full));
            }
            $checks[] = $this->guard('clamav', 'services', 'ClamAV', false, fn() => $this->checkClamav());
            $checks[] = $this->guard('cert', 'services', 'Lista CERT', false, fn() => $this->checkCert());
            $checks[] = $this->guard('feed', 'services', 'Wspólna baza spamu', false, fn() => $this->checkFeed());
            if ($full) {
                $checks[] = $this->guard('schema', 'system', 'Schemat bazy danych', false, fn() => $this->checkSchema());
            }
        }
        $checks[] = $this->guard('disk', 'system', 'Miejsce na dysku', false, fn() => $this->checkDisk());
        $checks[] = $this->guard('versions', 'system', 'Wersje', false, fn() => $this->checkVersions());

        return [
            'status' => self::overallStatus($checks),
            'checked_at' => $this->now()->format(DATE_ATOM),
            'full' => $full,
            'checks' => $checks,
        ];
    }

    /** Overall status of a list of checks (see the class comment). */
    public static function overallStatus(array $checks): string
    {
        $status = self::STATUS_OK;
        foreach ($checks as $check) {
            if ($check['status'] === self::FAIL && !empty($check['critical'])) {
                return self::STATUS_FAIL;
            }
            if ($check['status'] === self::FAIL || $check['status'] === self::WARN) {
                $status = self::STATUS_DEGRADED;
            }
        }
        return $status;
    }

    public static function check(string $key, string $group, string $label, string $status, string $message, array $details = [], bool $critical = false): array
    {
        return compact('key', 'group', 'label', 'status', 'message', 'critical', 'details');
    }

    // --- checks ---------------------------------------------------------------

    /** @return array{0:string, 1:string, 2?:array} status, message, details */
    private function checkDatabase(): array
    {
        $this->data->pingDatabase();
        $details = [];
        try {
            $details['size_bytes'] = $this->data->databaseSize();
        } catch (\Throwable $e) {
            $details['size_bytes'] = null;
        }
        $message = 'Połączenie działa';
        if ($details['size_bytes'] !== null) {
            $message .= ', rozmiar ' . self::formatBytes($details['size_bytes']);
        }
        return [self::OK, $message, $details];
    }

    private function checkScheduler(): array
    {
        $runs = $this->data->lastCronRuns();
        if (!$runs) {
            return [self::WARN, 'Brak wpisów w logu crona z ostatnich ' . CronRun::RETENTION_DAYS . ' dni - scheduler nie działa albo zadania nie są uruchamiane przez antispam:cron:run.'];
        }
        $newest = null;
        foreach ($runs as $run) {
            if ($newest === null || $run->getStartedAt() > $newest->getStartedAt()) {
                $newest = $run;
            }
        }
        $minInterval = null;
        foreach (self::JOBS as $command => $job) {
            if (isset($runs[$command])) {
                $interval = $this->jobInterval($this->data->recentCronRuns($command), $job['interval']);
                $minInterval = $minInterval === null ? $interval : min($minInterval, $interval);
            }
        }
        $minInterval = $minInterval ?? 15;
        $age = $this->ageSeconds($newest->getStartedAt());
        $limit = ($minInterval * 3 + 10) * 60;
        $details = ['last_run_at' => $newest->getStartedAt()->format(DATE_ATOM), 'last_command' => $newest->getCommand(), 'age_seconds' => $age, 'limit_seconds' => $limit];
        if ($age > $limit) {
            return [self::FAIL, 'Ostatnie zadanie crona uruchomiono ' . self::formatAge($age) . ' temu (' . $newest->getCommand() . ') - scheduler prawdopodobnie stoi.', $details];
        }
        return [self::OK, 'Działa, ostatnie zadanie ' . self::formatAge($age) . ' temu (' . $newest->getCommand() . ')', $details];
    }

    private function checkJob(string $command, int $defaultInterval): array
    {
        $runs = $this->data->recentCronRuns($command);
        if (!$runs) {
            return [self::SKIP, 'Brak uruchomień w logu crona (zadanie wyłączone albo jeszcze nie uruchomione).'];
        }
        $interval = $this->jobInterval($runs, $defaultInterval);
        $last = $runs[0];
        $age = $this->ageSeconds($last->getStartedAt());
        $details = [
            'last_run_at' => $last->getStartedAt()->format(DATE_ATOM),
            'age_seconds' => $age,
            'interval_minutes' => $interval,
            'last_exit_code' => $last->getExitCode(),
        ];

        $status = self::OK;
        $problems = [];
        if ($age > ($interval * 4 + 15) * 60) {
            $status = self::FAIL;
            $problems[] = 'ostatnie uruchomienie ' . self::formatAge($age) . ' temu (oczekiwane co ' . self::formatAge($interval * 60) . ')';
        } elseif ($age > ($interval * 2 + 5) * 60) {
            $status = self::WARN;
            $problems[] = 'ostatnie uruchomienie ' . self::formatAge($age) . ' temu (oczekiwane co ' . self::formatAge($interval * 60) . ')';
        }

        if ($last->isRunning()) {
            if ($age > max(self::STALE_RUN_SECONDS, $interval * 60 * 2)) {
                $status = self::worst($status, self::WARN);
                $problems[] = 'ostatnie uruchomienie nie zakończyło się (przerwane lub zawieszone)';
            }
        } else {
            $failed = 0;
            foreach ($runs as $run) {
                if ($run->isRunning()) {
                    continue;
                }
                if ($run->isSuccess()) {
                    break;
                }
                $failed++;
            }
            $details['consecutive_failures'] = $failed;
            if ($failed >= self::CONSECUTIVE_JOB_FAILURES) {
                $status = self::worst($status, self::FAIL);
                $problems[] = sprintf('%d ostatnie uruchomienia zakończone błędem (kod %d)', $failed, $last->getExitCode());
            } elseif ($failed > 0) {
                $status = self::worst($status, self::WARN);
                $problems[] = sprintf('ostatnie uruchomienie zakończone błędem (kod %d)', $last->getExitCode());
            }
        }

        $message = $problems ? ucfirst(implode('; ', $problems)) : 'OK, ostatnio ' . self::formatAge($age) . ' temu';
        return [$status, $message, $details];
    }

    /**
     * Background job queue (docs/jobs.md): a job waiting longer than
     * JobQueue::STUCK_* minutes means no worker (antispam:jobs:work) runs;
     * failed jobs of the last 24 h are a warning.
     */
    private function checkJobQueue(): array
    {
        $stats = $this->jobs->stats($this->now());
        $age = $stats['oldest_queued_at'] ? $this->ageSeconds($stats['oldest_queued_at']) : null;
        $details = [
            'queued' => $stats['queued'],
            'running' => $stats['running'],
            'failed_24h' => $stats['failed_24h'],
            'oldest_queued_age_seconds' => $age,
        ];
        $status = self::OK;
        $problems = [];
        if ($age !== null && $age > JobQueue::STUCK_FAIL_MINUTES * 60) {
            $status = self::FAIL;
            $problems[] = 'najstarsze zadanie czeka ' . self::formatAge($age) . ' - worker (antispam:jobs:work) nie działa';
        } elseif ($age !== null && $age > JobQueue::STUCK_WARN_MINUTES * 60) {
            $status = self::WARN;
            $problems[] = 'najstarsze zadanie czeka ' . self::formatAge($age) . ' - worker (antispam:jobs:work) nie działa albo jest zajęty długim zadaniem';
        }
        if ($stats['failed_24h'] > 0) {
            $status = self::worst($status, self::WARN);
            $last = $stats['last_failed'];
            $problems[] = sprintf('%d zadań zakończonych błędem w ciągu 24 h (ostatnie #%d %s: %s)', $stats['failed_24h'], $last['id'] ?? 0, $last['label'] ?? '', mb_substr((string)($last['error'] ?? ''), 0, 200));
        }
        $message = $problems
            ? ucfirst(implode('; ', $problems))
            : sprintf('OK - w kolejce %d, w trakcie %d', $stats['queued'], $stats['running']);
        return [$status, $message, $details];
    }

    private function checkAccount(Account $account, bool $full): array
    {
        $details = ['type' => $account->getConnectionType(), 'name' => $account->getName()];
        if ($account->isSsh() && !$account->getAgentDeployed()) {
            return [self::WARN, 'Agent SSH nie jest wdrożony - skrzynka nie jest skanowana.', $details];
        }

        $status = self::OK;
        $messages = [];
        if ($account->isOAuth()) {
            // Token state of OAuth accounts (Microsoft 365 / Google, docs/oauth.md).
            $details['auth'] = $account->getImapAuthMethod();
            $details['oauth_connected'] = $account->isOAuthConnected();
            $details['oauth_error'] = $account->getOAuthError();
            if (!$account->isOAuthConnected()) {
                $status = self::FAIL;
                $messages[] = 'Konto OAuth nie jest połączone - użyj „Połącz” na stronie edycji konta';
            } elseif ($account->getOAuthError()) {
                $status = self::FAIL;
                $messages[] = 'Odświeżenie tokenu OAuth nieudane: ' . mb_substr((string)$account->getOAuthError(), 0, 200);
            }
        }
        $last = $account->getLastScanAt();
        $maxAge = $this->settings->getScanMaxAge() * 60;
        if (!$last) {
            $status = self::WARN;
            $messages[] = 'Jeszcze nie było udanego skanu';
            $details['last_scan_at'] = null;
        } else {
            $age = $this->ageSeconds($last);
            $details['last_scan_at'] = $last->format(DATE_ATOM);
            $details['last_scan_age_seconds'] = $age;
            if ($age > $maxAge) {
                $status = self::FAIL;
                $messages[] = 'Ostatni udany skan ' . self::formatAge($age) . ' temu (limit ' . self::formatAge($maxAge) . ') - skanowanie nie działa, sprawdź log crona.';
            } else {
                $messages[] = 'Ostatni skan ' . self::formatAge($age) . ' temu';
            }
            $result = $account->getLastScanResultDecoded();
            $errors = is_array($result) ? array_values(array_filter((array)($result['errors'] ?? []))) : [];
            if ($errors) {
                $status = self::worst($status, self::WARN);
                $details['last_scan_errors'] = count($errors);
                $messages[] = count($errors) . ' błąd(ów) w ostatnim skanie: ' . mb_substr((string)$errors[0], 0, 200);
            }
            if (is_array($result) && !empty($result['agent_warning'])) {
                $status = self::worst($status, self::WARN);
                $messages[] = (string)$result['agent_warning'];
            }
        }

        if ($full) {
            [$liveStatus, $liveMessage, $liveDetails] = $account->isSsh() ? $this->probeSsh($account) : $this->probeImap($account);
            $status = self::worst($status, $liveStatus);
            $messages[] = $liveMessage;
            $details += $liveDetails;
        }

        return [$status, implode('. ', $messages), $details];
    }

    private function probeImap(Account $account): array
    {
        try {
            $this->imap->connect($account)->close();
            return [self::OK, 'Logowanie IMAP działa', ['imap_login' => true]];
        } catch (\Throwable $e) {
            return [self::FAIL, 'Logowanie IMAP nieudane: ' . mb_substr($e->getMessage(), 0, 300), ['imap_login' => false]];
        }
    }

    private function probeSsh(Account $account): array
    {
        try {
            $health = $this->ssh->runHealth($account);
        } catch (\Throwable $e) {
            return [self::FAIL, 'Agent SSH nieosiągalny: ' . mb_substr($e->getMessage(), 0, 300), ['agent_reachable' => false]];
        }
        if (!is_array($health) || empty($health['success'])) {
            return [self::FAIL, 'Agent SSH: ' . mb_substr((string)($health['error'] ?? 'nieprawidłowa odpowiedź'), 0, 300), ['agent_reachable' => false]];
        }
        $details = [
            'agent_reachable' => true,
            'agent_version' => $health['agent_version'] ?? null,
            'agent_php' => $health['php'] ?? null,
            'agent_last_scan' => $health['rules']['last_scan'] ?? null,
            'agent_db_size_bytes' => $health['db_size_bytes'] ?? null,
        ];
        if (!empty($health['agent_outdated'])) {
            return [self::WARN, (string)($health['agent_warning'] ?? 'Agent w starszej wersji - wdróż go ponownie.'), $details];
        }
        return [self::OK, 'Agent SSH odpowiada (wersja ' . ($details['agent_version'] ?? '?') . ')', $details];
    }

    private function checkClamav(): array
    {
        if (!$this->scoring->isScoringEnabled() || !$this->scoring->isClamavEnabled()) {
            return [self::SKIP, 'Wyłączony'];
        }
        $dsn = $this->scoring->getClamavDsn() ?: ClamavService::DEFAULT_DSN;
        if ($this->clamav->ping($dsn, self::CLAMAV_TIMEOUT)) {
            return [self::OK, 'Odpowiada (' . $dsn . ')', ['dsn' => $dsn]];
        }
        return [self::FAIL, 'Nie odpowiada na PING (' . $dsn . ') - załączniki nie są skanowane antywirusem.', ['dsn' => $dsn]];
    }

    private function checkCert(): array
    {
        if (!$this->cert->isEnabled()) {
            return [self::SKIP, 'Wyłączona'];
        }
        $status = $this->cert->getStatus();
        $details = ['count' => $status['count'], 'last_sync_at' => $status['last_sync_at']];
        $synced = self::parseDate($status['last_sync_at']);
        if (!$synced) {
            return [self::FAIL, 'Lista nigdy nie została pobrana' . ($status['last_error'] ? ': ' . $status['last_error'] : '') . '.', $details];
        }
        $age = $this->ageSeconds($synced);
        $details['age_seconds'] = $age;
        if ($age > self::CERT_FAIL_HOURS * 3600) {
            return [self::FAIL, 'Lista nieaktualna - ostatnia udana synchronizacja ' . self::formatAge($age) . ' temu' . ($status['last_error'] ? ' (' . $status['last_error'] . ')' : '') . '.', $details];
        }
        $attempt = self::parseDate($status['last_attempt_at']);
        if ($age > self::CERT_WARN_HOURS * 3600 || ($status['last_error'] && $attempt && $attempt > $synced)) {
            return [self::WARN, 'Ostatnia udana synchronizacja ' . self::formatAge($age) . ' temu' . ($status['last_error'] ? ', ostatni błąd: ' . $status['last_error'] : '') . '.', $details];
        }
        return [self::OK, $status['count'] . ' domen, synchronizacja ' . self::formatAge($age) . ' temu', $details];
    }

    private function checkFeed(): array
    {
        if (!$this->feed->isEnabled()) {
            return [self::SKIP, 'Wyłączona'];
        }
        if ($this->feed->getRemoteUrl() === '') {
            return [self::SKIP, 'Włączona bez zdalnego huba - nie ma czego synchronizować.'];
        }
        $pull = $this->feed->getLastPullAt();
        $details = ['last_pull_at' => $pull ? $pull->format(DATE_ATOM) : null];
        $run = $this->data->lastSuccessfulCronRun('antispam:feed:sync');
        if (!$run) {
            return [self::WARN, 'Brak udanej synchronizacji w logu crona (' . CronRun::RETENTION_DAYS . ' dni).', $details];
        }
        $age = $this->ageSeconds($run->getStartedAt());
        $details['last_sync_at'] = $run->getStartedAt()->format(DATE_ATOM);
        $details['age_seconds'] = $age;
        if ($age > self::FEED_FAIL_HOURS * 3600) {
            return [self::FAIL, 'Ostatnia udana synchronizacja ' . self::formatAge($age) . ' temu.', $details];
        }
        if ($age > self::FEED_WARN_HOURS * 3600) {
            return [self::WARN, 'Ostatnia udana synchronizacja ' . self::formatAge($age) . ' temu.', $details];
        }
        return [self::OK, 'Synchronizacja ' . self::formatAge($age) . ' temu', $details];
    }

    private function checkSchema(): array
    {
        $pending = $this->data->pendingSchemaChanges();
        if ($pending) {
            return [self::WARN, count($pending) . ' zmian(y) schematu czeka - uruchom php bin/console antispam:db:upgrade (kontener app robi to przy starcie); jeśli migracje są aktualne, brakuje migracji dla zmiany encji (docs/migrations.md).', ['pending' => count($pending), 'sql' => array_slice($pending, 0, 20)]];
        }
        return [self::OK, 'Zgodny z encjami', ['pending' => 0]];
    }

    private function checkDisk(): array
    {
        $disk = $this->data->diskSpace();
        if ($disk['free'] === null) {
            return [self::SKIP, 'Nie udało się odczytać wolnego miejsca'];
        }
        $details = ['free_bytes' => $disk['free'], 'total_bytes' => $disk['total']];
        $message = 'Wolne ' . self::formatBytes($disk['free']) . ($disk['total'] ? ' z ' . self::formatBytes($disk['total']) : '') . ' (var/)';
        if ($disk['free'] < self::DISK_FAIL_BYTES) {
            return [self::FAIL, $message, $details];
        }
        if ($disk['free'] < self::DISK_WARN_BYTES || ($disk['total'] && $disk['free'] / $disk['total'] < self::DISK_WARN_RATIO)) {
            return [self::WARN, $message, $details];
        }
        return [self::OK, $message, $details];
    }

    private function checkVersions(): array
    {
        $details = [
            'app' => \AntispamBundle\AppVersion::VERSION,
            'plugin' => PluginApiController::PLUGIN_VERSION,
            'agent' => SshService::bundledAgentVersion(),
            'php' => PHP_VERSION,
        ];
        return [self::OK, sprintf('Aplikacja %s, wtyczki %s, agent %s, PHP %s', $details['app'], $details['plugin'], $details['agent'] ?? '?', $details['php']), $details];
    }

    // --- helpers --------------------------------------------------------------

    /** Runs one check; an exception becomes a failing check instead of a 500. */
    private function guard(string $key, string $group, string $label, bool $critical, callable $fn): array
    {
        try {
            $r = $fn();
            return self::check($key, $group, (string)$label, $r[0], $r[1], $r[2] ?? [], $critical);
        } catch (\Throwable $e) {
            return self::check($key, $group, (string)$label, self::FAIL, 'Błąd: ' . mb_substr($e->getMessage(), 0, 300), [], $critical);
        }
    }

    /**
     * Interval of a job in minutes: median gap between its latest starts,
     * or the scheduler default when there is not enough history.
     *
     * @param CronRun[] $runs newest first
     */
    private function jobInterval(array $runs, int $default): int
    {
        $gaps = [];
        for ($i = 1; $i < count($runs); $i++) {
            $gap = $runs[$i - 1]->getStartedAt()->getTimestamp() - $runs[$i]->getStartedAt()->getTimestamp();
            if ($gap > 0) {
                $gaps[] = $gap;
            }
        }
        if (count($gaps) < 2) {
            return $default;
        }
        sort($gaps);
        return max(1, (int)round($gaps[intdiv(count($gaps), 2)] / 60));
    }

    private function ageSeconds(\DateTimeInterface $at): int
    {
        return max(0, $this->now()->getTimestamp() - $at->getTimestamp());
    }

    private function now(): \DateTimeImmutable
    {
        return $this->now ?? new \DateTimeImmutable();
    }

    private static function worst(string $a, string $b): string
    {
        $rank = [self::SKIP => 0, self::OK => 1, self::WARN => 2, self::FAIL => 3];
        return $rank[$b] > $rank[$a] ? $b : $a;
    }

    private static function parseDate($value): ?\DateTimeImmutable
    {
        if (!$value) {
            return null;
        }
        try {
            return new \DateTimeImmutable((string)$value);
        } catch (\Exception $e) {
            return null;
        }
    }

    public static function formatAge(int $seconds): string
    {
        if ($seconds < 120) {
            return $seconds . ' s';
        }
        if ($seconds < 7200) {
            return round($seconds / 60) . ' min';
        }
        if ($seconds < 172800) {
            return round($seconds / 3600) . ' h';
        }
        return round($seconds / 86400) . ' dni';
    }

    public static function formatBytes(?int $bytes): string
    {
        if ($bytes === null) {
            return '?';
        }
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $v = (float)$bytes;
        while ($v >= 1024 && $i < count($units) - 1) {
            $v /= 1024;
            $i++;
        }
        return ($i === 0 ? (string)$bytes : number_format($v, 1, ',', '')) . ' ' . $units[$i];
    }
}
