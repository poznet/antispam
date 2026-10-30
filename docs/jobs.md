# Background jobs ("Zadania w tle")

Heavy operations started from the panel - anything that logs in to a mailbox,
talks to an SSH agent or downloads / sends a lot - do **not** run inside the
HTTP request. The button queues a **background job** and redirects to the job
page; a worker process (`antispam:jobs:work`) runs it within seconds. This
replaced the synchronous "Skanuj" that ended in `504 Gateway Timeout` on the
first scan of a big mailbox.

| What | Where |
| --- | --- |
| Table | `antispam_job` (entity `BackgroundJob`, migration `Version20261028201942`) |
| Queue | `Services\Jobs\JobQueue` (enqueue / dedupe / cancel / stats / purge, plain DBAL) |
| Worker | `Services\Jobs\JobWorker`, command `antispam:jobs:work` (alias `antispam:jobs:run`) |
| Handlers | `Services\Jobs\Handler\*` (`JobHandlerInterface`, tag `antispam.job_handler`, autoconfigured) |
| Panel | **Przegląd → Zadania w tle** (`/jobs/`), job page `/jobs/{id}`, JSON `/jobs/{id}/status` |

## What is queued

| Panel action | Job type | Notes |
| --- | --- | --- |
| Konta → **Skanuj** | `account.scan` | IMAP: resumable batches (below); SSH: one agent `scan` |
| Konta → **↻ Przeskanuj całą skrzynkę ponownie**, weekly rescan (`antispam:rescan:due`) | `account.rescan` | whole INBOX again with the current rules, batches for IMAP and SSH (agent 3.3+); [spam-handling.md](spam-handling.md#full-rescan) |
| Konta → **Wdróż** (SSH) | `account.deploy` | upload + test the agent, then push rules and settings |
| Konta → **Synchronizuj** (SSH) | `account.sync` | rules + settings to the agent |
| Konta → **Stan** (SSH) | `account.health` | agent `health` |
| New rule on **Blacklista domen / e-mail**, **Phishing → Zablokuj** | `rule.retroactive` | `RetroactiveSpamService::applyRule()` - mail already in INBOX ([spam-handling.md](spam-handling.md#retroactive-blacklist)) |
| Plugin spam / phishing report that adds a blacklist rule | `rule.retroactive` | requester = the mailbox (actor `plugin`); the API still answers `"retroactive": "scheduled"` |
| Rule change in the user area (`/my/rules`, "Zawsze akceptuj" in `/my/spam`) of an SSH mailbox | `account.sync` | background only (no job page for the user); a failure is a failed job |
| **Zmień na: Wszystkie skrzynki** on a rule list (one rule, checked rules, every rule of a mailbox) | `rule.retroactive` per moved blacklist rule + `account.sync` per deployed SSH agent | the pass of a global rule covers every account and the legacy mailbox; [scoring.md](scoring.md#making-a-rule-global) |
| Lista CERT → **Synchronizuj teraz** | `cert.sync` | download + replace the CERT Polska list |
| Raport kwarantanny → **Wyślij teraz** | `digest.send` | reads every quarantine, sends the digests |
| Phishing → bulk **Wyślij zaznaczone** | `phishing.forward` | one e-mail per report |
| Stan systemu → **Sprawdź teraz** (full check) | `health.full` | IMAP login to every account, every SSH agent; the job page links to the report (`/system/status?job={id}`) |
| Kwarantanna (admin and `/my/quarantine`) → **Usuń wszystkie wysokiego ryzyka** / **Usuń wszystko z kwarantanny**, admin **... (wszystkie skrzynki)** | `quarantine.purge` | permanent deletion from one mailbox's quarantine, mode `high_risk` / `all` decided at run time; IMAP `QuarantineService::purge()`, SSH agent 3.4 `quarantine-purge`; result: total / deleted / skipped / failed ([spam-handling.md](spam-handling.md#bulk-deletion)) |

Still synchronous, on purpose: **Test** of an account (short timeouts: IMAP
open 10 s / read 20 s, SSH 15 s connect + 20 s per command), the IMAP/TLS check
of the account form, releasing / deleting **one** quarantined or spam message,
forwarding **one** phishing report, the ClamAV and alert tests. Listing pages
(Folder spamu, Kwarantanna, `/my/quarantine`) read the mailboxes with their
own limits and timeouts.

## Dedupe

A job may carry a dedupe key (`account.scan:<account id>`, `account.rescan:<account id>`, `retro:<rule>:<id>`,
`cert.sync`, `quarantine.purge:<mailbox key>:<mode>`, ...). While a job with that key is **queued** - and, for
*exclusive* types, also while it is **running** - the key sits in the unique
column `active_key`, so a second click gets the existing job back
("to zadanie jest już w kolejce / w trakcie wykonywania"). Exclusive: scan, full rescan,
deploy, health, retroactive pass, CERT sync, digest, full health check, quarantine purge.
Not exclusive: `account.sync` (a rule change during a running sync must queue
another one - the running sync may have exported the rules before the change)
and `phishing.forward`.

## The job page

`/jobs/{id}` shows status, progress (text, `done/total` bar), requester and
times. While the job is queued / running `Resources/public/js/job-status.js`
polls `/jobs/{id}/status` every 2 s (no inline script - CSP) and reloads the
page when it ends; the result is rendered by
`Resources/views/Job/result/<type>.html.twig` (the former
`Account/scan|deploy|sync|health.html.twig` content). **Anuluj** (job page and,
since 2.1.0, every active row of the job list) cancels a queued job at once; a
running one stops at its next check. The worker exposes the running job through
`Jobs\JobCancellation` (asked at most every 5 s), so an IMAP scan / rescan
batch stops **at the next message** - the rescan keeps its cursor and the
account's progress, a later rescan continues it - and a quarantine purge stops
within 50 messages (counts so far kept). A single SSH agent command finishes. The account list shows a
"Skanowanie skrzynki: w kolejce / trwa" badge per account with an active job.

Access: `ROLE_ADMIN` only (`#[IsGranted]` + the `^/` access rule). The one
user-area job is the quarantine purge from `/my/quarantine`: it gets its own
page in the user area, `/my/jobs/{id}` (+ `/my/jobs/{id}/status` for
`job-status.js`, `MyController`), which shows only `quarantine.purge` jobs of a
mailbox the user owns **and** queued by that user (`requested_by` = login,
`requested_by_type` = `user`); anything else is a 404. **Anuluj** there too
(`/my/jobs/{id}/cancel`, own jobs only, audit `job.cancel` with `source: my`),
raw error text only for admins. A click while an admin's purge of the same mailbox
and mode is queued does not open that job (flash on `/my/quarantine` instead).

## Worker

```bash
php bin/console antispam:jobs:work --time-limit=3600     # loop: polls every 2 s
php bin/console antispam:jobs:run --once                 # run what is due, then exit (cron)
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--once` | - | exit as soon as the queue is empty (time limit 50 s) |
| `--time-limit` | 0 (forever) | stop *starting* jobs after N s; the running one may take up to `--job-timeout` more |
| `--memory-limit` | 256 | exit after a job when memory use is above N MB |
| `--sleep` | 2 | seconds between polls of an empty queue |
| `--job-timeout` | env `JOBS_JOB_TIMEOUT` or 3900 | one job may run N s (`pcntl_alarm`; the job is marked failed and the worker exits) - the SSH agent scan may take 3600 s |
| `--batch-seconds` | env `JOBS_BATCH_SECONDS` or 120 | length of one batch of an IMAP scan |

- **Claiming** is a conditional `UPDATE ... WHERE status = 'queued'`, so several
  workers never run the same job (one worker is enough).
- **Heartbeat / stale jobs:** a running job updates `heartbeat_at` with its
  progress. At start and every minute while idle the worker recovers jobs whose
  worker died (container restart, OOM, `timeout` kill): the worker process is
  gone (same host, `posix_kill`) or the heartbeat is older than the job timeout
  + 5 min. Such a job is queued again (`interruptions` + 1); after 3
  interruptions it fails ("Proces wykonujący zadanie został przerwany 3 razy").
  A resumed scan continues from its stored cursor.
- After every job the EntityManager is cleared (or reset when a failed flush
  closed it). **Before** every job (and every batch of a resumable one) the
  rules / settings the services keep for the process lifetime are dropped
  (`RuntimeCacheInterface`, tag `antispam.runtime_cache`: white / blacklist
  listeners, impersonation VIPs, `ScoringService` lists, `ConfigService`), so a
  rule or threshold changed in the panel applies to the next job, not only
  after the worker restarts. (Up to 2.0.0 a rule added while the worker ran was
  invisible to its scans and rescans for up to an hour.) Deliberately not
  Symfony's `kernel.reset`: `BayesService::reset()` wipes the learned tokens.
- SIGTERM / SIGINT finish the current job, then exit.

### Docker

`docker/scheduler.sh` (service `scheduler` in `docker-compose.prod.yml`) starts
the worker next to the minute ticks: a loop restarted whenever the worker exits,
guarded by `flock /tmp/antispam-jobs-worker.lock`, wrapped in
`timeout -k 30 $((JOBS_WORKER_TIME_LIMIT + JOBS_JOB_TIMEOUT + 60))` as the hard
backstop. A click is picked up within ~2 s.

| Variable | Default | |
| --- | --- | --- |
| `JOBS_WORKER` | `on` | `off` = no worker in this container (run it elsewhere) |
| `JOBS_WORKER_TIME_LIMIT` | `3600` | the worker exits and is restarted fresh |
| `JOBS_JOB_TIMEOUT` | `3900` | per-job limit |
| `JOBS_BATCH_SECONDS` | `120` | IMAP scan batch length |
| `SCAN_MAX_SECONDS` | `600` | time budget of one IMAP mailbox per `scan-all` run |

The image now includes `pcntl` (per-job time limit, clean shutdown). With only
the `docker-compose.yml` stack (no scheduler) nothing runs the jobs - use the
prod compose file or a cron entry.

### Without Docker

Either a crontab entry (picked up within a minute):

```
* * * * * php /path/to/bin/console antispam:jobs:run --once
```

or a supervised long-running worker (systemd / supervisord), e.g.

```ini
[Service]
ExecStart=/usr/bin/php /path/to/bin/console antispam:jobs:work --time-limit=3600
Restart=always
User=www-data
```

Run it as the web server user: the scan locks and markers in `var/data` must
be shared with the panel.

## Big first scans (batches)

The first scan of a mailbox reads the whole INBOX. `ImapScanService::scan()`
takes a message limit / deadline: a whole-INBOX or incremental pass stops after
the deadline, stores the cursor at the last processed UID and reports
`remaining`. The scan job then re-queues itself with the counters so far
(`state` column) and the next batch continues above the cursor ("Przetworzono
2000 wiadomości, zostało 18000"). Other jobs get their turn between batches.

- The account is marked as scanned (`lastScanAt`, result on the account list)
  only when the last batch is done. Until then every batch still runs as the
  **initial scan** (kept out of the statistics), and the counters on the job
  page are the sum of all batches.
- A failed message keeps the cursor just below it, so the next batch retries it
  (as between two normal scans).
- A "since the last scan" pass (no cursor, upgrade, changed UIDVALIDITY) is
  never cut - it is small and must not leave the cursor below older mail.
- SSH accounts: the agent scans the Maildir in one command (up to 3600 s) and
  marks every message in its own database, so a timed-out scan continues on the
  next run.

## Full rescan (batches)

`account.rescan` (`Handler\AccountRescanHandler`) works like the batched first
scan, with its own progress: IMAP passes go through
`ImapScanService::rescanAccount()` with a rescan cursor kept in the job `state`
(`uidvalidity`, `last_uid`, `until_uid` = highest UID listed when the rescan
started, `left` = messages not checked yet), mirrored after every batch to
`Account::rescanProgress` so a later job continues an interrupted rescan; a
failed batch is retried (`AccountRescanHandler::RETRY_DELAYS`),
never the account's scan cursor; SSH passes call the agent's `rescan
--time-limit=<batch> [--reset]` (the agent keeps its own progress). Counters are
summed over the batches; when the last one is done the result goes to the job
and to `Account::lastRescanAt` / `lastRescanResult` (also on failure, with
`error`) - never to `lastScanAt` / `lastScanResult`, so the dashboard and the
"last scan" health check ignore it. A busy mailbox lock makes it wait like a
scan. scan-all does not skip a mailbox with an active rescan job: they take
turns on the lock, and the rescan never moves the scan cursor. Behaviour and
rules: [spam-handling.md](spam-handling.md#full-rescan).

## Concurrency with the scheduled scan

Both the scan job and `antispam:agent:scan-all` go through
`Services\AccountScanner` and the same per-mailbox lock
(`flock` on `var/data/locks/imap-scan-*.lock`, `ImapScanService::accountLockName()`;
the SSH agent has its own lock next to its database). A busy mailbox throws
`ScanLockedException`:

- the **scan job** waits in the queue and retries every 30 s (progress "Czeka:
  skrzynkę skanuje teraz inny proces"), giving up after an hour;
- **scan-all** skips the mailbox ("skipped (...)", not an error, exit code
  unaffected) and also skips mailboxes with an active panel scan job (queued
  less than an hour ago or running), so the cursor is advanced by one process
  at a time. A job queued for over an hour (no worker) no longer blocks the
  scheduled scan.
- scan-all gives each IMAP mailbox at most `--max-seconds` (env
  `SCAN_MAX_SECONDS`, default 600) per run; the rest of a huge INBOX is scanned
  on the next run, with the same "initial until finished" rule.

## Audit log

Jobs that were audited before keep their audit entries, written when the job
**finishes**, with the requester as actor (`requested_by` / `requested_by_type`
copied from the user who clicked) and the job id in the details:
`account.deploy`, `account.sync` (panel only), `cert.sync`,
`phishing.forward`, `account.rescan` (also `account.rescan_queued` when it is
queued; actor `harmonogram` for the weekly rescan), `quarantine.purge` (also
`quarantine.purge_queued` when it is queued). The client IP is empty (the worker has no request).
Cancelling a job is `job.cancel`. See [audit.md](audit.md).

## Health, doctor, metrics

- Health check `jobs` (group *Zadania okresowe*, not critical,
  [health.md](health.md)): the oldest *due* queued job waiting > 10 min = `warn`,
  > 60 min = `fail` ("worker (antispam:jobs:work) nie działa"); failed jobs in
  the last 24 h = `warn` with the last error.
- `/metrics`: `antispam_jobs_queued`, `antispam_jobs_running`,
  `antispam_jobs_failed_24h`, `antispam_jobs_oldest_queued_age_seconds`.
- `antispam:doctor` check `jobs`: queue stuck for > 10 min or failed jobs in
  24 h = WARN with a hint.
- The job page and the list warn as well when jobs wait longer than 10 min.

## Retention

`antispam:purge` deletes **finished** jobs (done / failed / cancelled) older
than `jobs.retention_days` (config table, default **30**, `0` = keep forever).
Queued and running jobs are never deleted.

## Adding a job type

1. Add `BackgroundJob::TYPE_*` + its label in `BackgroundJob::TYPES`.
2. Write a handler implementing `JobHandlerInterface` in `Services/Jobs/Handler/`
   (autoconfigured): `type()`, `exclusive()`, `handle(JobContext)` returning the
   result array (or throwing). Report progress with `$context->progress()`;
   long work can split itself with `$context->continueLater($state, $delay)`.
3. Add `Resources/views/Job/result/<type>.html.twig` (the generic JSON view is
   the fallback).
4. In the controller: `$queued = $this->jobs->enqueue(TYPE, payload, account, label, dedupeKey)`
   and `return $this->redirectToJob($queued, 'Co')` (`Controller\JobQueueTrait`).
