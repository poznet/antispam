# Health checks and alerting

Watches the installation after deployment: is the database up, does the
scheduler run, are mailboxes actually scanned, are ClamAV / the CERT list /
the shared feed alive. Results are available to an external uptime monitor
(`/health`), to Prometheus (`/metrics`), on the admin page **Przegląd → Stan
systemu** (`/system/status`) and as e-mail / webhook alerts sent by
`antispam:health:check`.

Code: `Services/HealthService.php` (checks, reusable - e.g. by a doctor
command), `Services/HealthDataSource.php` (queries), `Services/HealthAlerter.php`
(alert state machine), `Services/HealthMetrics.php` (Prometheus),
`Services/HealthSettings.php`, `Controller/HealthController.php`,
`Command/HealthCheckCommand.php`.

## Checks

Every check has a status `ok`, `warn`, `fail` or `skip` (feature disabled / not
applicable). The overall status is:

- `fail` - a **critical** check fails: database unreachable, or the scheduler
  stopped (no cron job started for 3x the shortest job interval + 10 min);
- `degraded` - any other check fails or warns;
- `ok` - otherwise.

One mailbox with a changed password therefore makes the service `degraded`,
not `fail`.

| Key | What | Quick | Full |
|---|---|---|---|
| `db` (critical) | `SELECT 1`; database size from `information_schema` (MySQL/MariaDB) | yes | yes |
| `scheduler` (critical) | age of the newest run in the cron log (`antispam_cron_run`); no runs at all = `warn` | yes | yes |
| `cron:<command>` | per scheduler job (scan-all, health:check, feed:sync, cert:sync, digest:send, purge): late start (`warn` > 2x interval + 5 min, `fail` > 4x + 15 min), last run failed (`warn`), 3 failed runs in a row (`fail`), run without end > 2 h (`warn`). The interval is the median gap between the last runs (falls back to the scheduler defaults), so a custom `SCAN_INTERVAL` needs no setting. No runs in 14 days = `skip` | yes | yes |
| `account:<id>` | last **successful** scan age (`Account.lastScanAt`; failed scans do not update it) vs **Maks. wiek skanu** (default 60 min) = `fail`; never scanned / SSH agent not deployed / errors or "outdated agent" warning in the last scan result = `warn` | yes | + IMAP login (IMAP accounts) or `health` command of the agent (SSH accounts: reachability, agent version) |
| `clamav` | `PING` to clamd (3 s timeout) when ClamAV scanning is enabled | yes | yes |
| `cert` | CERT list: never synced or last success > 72 h = `fail`; > 18 h, or the last attempt failed = `warn` | yes | yes |
| `feed` | shared feed with a remote hub: last **successful** `antispam:feed:sync` in the cron log > 2 h `warn`, > 24 h `fail` | yes | yes |
| `schema` | statements `doctrine:schema:update --force` would still run (DROPs ignored) = `warn` | - | yes |
| `disk` | free space of the filesystem holding `var/`: < 500 MB `fail`, < 2 GB or < 5 % `warn` | yes | yes |
| `versions` | mail client plugin version, bundled agent version, PHP (always `ok`; TODO: application version once it exists) | yes | yes |

A check that throws becomes `fail` with the error message, it never breaks the
endpoint. When the database is down only `db`, `disk` and `versions` run.

The quick check costs a handful of queries plus the ClamAV ping. The full one
logs in to every IMAP account and queries every SSH agent (seconds per
account), so it runs only on demand: **Sprawdź teraz** on the page, `/health?token=…&full=1`
or `antispam:health:check --full`.

The legacy mailbox from *Konfiguracja → E-mail* has no per-account scan time
and is not checked (the `scan-all` job fails when it cannot be scanned).

## Endpoints

| Path | Access | Answer |
|---|---|---|
| `GET /health` | public | `{"status":"ok"}` / `degraded` / `fail`, nothing else. HTTP 200, **503 when `fail`**. Computed at most every 30 s (cache). |
| `GET /health?token=…` | token | full report as JSON (`status`, `checked_at`, `full`, `checks[]` with `key`, `group`, `label`, `status`, `message`, `critical`, `details`). `&full=1` = full check. Wrong token = 403. |
| `GET /metrics?token=…` | token | Prometheus text format 0.0.4. Without / with a wrong token = 403. |

The token may also be sent as `Authorization: Bearer <token>`. It comes from the
`HEALTH_TOKEN` environment variable or, when that is empty, from the field on
the Stan systemu page (min. 16 characters: letters, digits, `. _ ~ -`).
No token configured = details and metrics disabled; `/health` still works.
Generate one with `openssl rand -hex 24`.

Both paths are `PUBLIC_ACCESS` in `config/packages/security.yaml` (exactly
`^/(health|metrics)$`); responses carry `Cache-Control: no-store`.

### Metrics

```
antispam_health_status                         0 ok, 1 degraded, 2 fail
antispam_health_check_status{check,group}      0 ok, 1 warn, 2 fail (skip omitted)
antispam_account_last_scan_age_seconds{account,type}
antispam_cron_last_run_age_seconds{command}
antispam_scans_24h                             runs of antispam:agent:scan-all
antispam_cron_runs_24h{command}
antispam_cron_failures_24h{command}            non-zero exit codes
antispam_decisions_24h{decision}               score log (initial scans excluded)
antispam_quarantined_24h{account}              score log outcome "quarantined"
antispam_database_size_bytes                   MySQL/MariaDB only
antispam_disk_free_bytes
antispam_metrics_activity_error                1 when the 24h counters could not be read
```

Quarantine counts come from the score log (what was moved to quarantine in the
last 24 h); listing the quarantine folders themselves would need an IMAP/SSH
connection per mailbox.

Prometheus:

```yaml
scrape_configs:
  - job_name: antispam
    scheme: https
    metrics_path: /metrics
    authorization:
      credentials: <HEALTH_TOKEN>
    static_configs:
      - targets: ['antispam.example.com']
```

## Uptime monitor setup

Point any HTTP monitor (Uptime Kuma, UptimeRobot, Better Stack, Zabbix web
scenario...) at `https://antispam.example.com/health`, interval 1-5 min:

- "up" = HTTP 200; HTTP 503 means `fail` (database or scheduler down);
- to also be told about `degraded`, use a keyword check for `"status":"ok"`;
- the public answer holds no details, so the URL can be shared.

## Alerts

`antispam:health:check` runs the quick check and sends a notification when a
check changes state. In Docker the scheduler runs it every
`HEALTH_CHECK_INTERVAL` minutes (default 15, `0` = off) through
`antispam:cron:run`, so each run is in the cron log. The command exits 0 even
when checks fail (a failing installation should not also look like a failing
job); `--exit-code` returns 1 for degraded and 2 for fail, `--no-alert` only
prints, `--json` prints the report, `--full` adds the slow checks.

Behaviour:

- a check is **failing** when its status is `fail` (or `warn` with
  *Alarmuj także przy ostrzeżeniach*);
- an alert is sent once the check failed **Próg** consecutive runs (default 2,
  i.e. ~30 min with the default interval); a check that flaps below the
  threshold never alerts;
- while it keeps failing nothing is repeated;
- when it passes again one recovery message is sent and the state is cleared;
- all new problems and recoveries of one run go out in one notification;
- if every configured channel fails, the alert is not marked as sent and the
  next run tries again (the error is shown on the page); when at least one
  channel worked it counts as sent;
- with no channel configured problems are still counted and shown, nothing is
  sent;
- with alerts disabled failures are still counted; enabling alerts while a
  check is failing alerts on the next run;
- while the database check fails, the state of the checks that were not run is
  kept (no false recoveries); checks that disappear while the database is up
  (deleted account) are dropped silently.

State is stored in the config table under `health.alert_state`.

### Channels

- **E-mail** via Symfony Mailer (`MAILER_DSN`). Recipients: *E-mail odbiorcy*
  (comma separated), default the sender address of the quarantine digest
  (`digest.from_email`), which is also the From address (else the first
  recipient). The text links to `<digest.base_url>/system/status` when the
  digest base URL is set.
- **Webhook**: `POST` with `Content-Type: application/json`, 10 s timeout, no
  redirects, http/https only. Payload:

```json
{
  "text": "[Antispam] Problem: ClamAV\nNowe problemy:\n- [FAIL] ClamAV: Nie odpowiada ...",
  "type": "problem",
  "status": "degraded",
  "checked_at": "2026-10-28T12:00:00+00:00",
  "instance": "https://antispam.example.com",
  "problems": [{"key": "clamav", "label": "ClamAV", "status": "fail", "message": "...", "since": "2026-10-28T11:30:00+00:00"}],
  "recovered": []
}
```

`type` is `problem` (at least one new problem), `recovery` or `test`. The
`text` field is what Slack, Mattermost and Microsoft Teams incoming webhooks
display; the other fields are for custom receivers (n8n, Zabbix, own scripts).

**Wyślij testowy alert** sends a test message through every configured channel.

### Settings (config table)

| Key | Default | Form field |
|---|---|---|
| `health.alert_enabled` | on | Wysyłaj alerty |
| `health.alert_on_warn` | off | Alarmuj także przy ostrzeżeniach |
| `health.alert_email` | (digest sender) | E-mail odbiorcy |
| `health.webhook_url` | - | Webhook |
| `health.fail_threshold` | 2 | Próg (kolejne błędy), 1-100 |
| `health.scan_max_age` | 60 | Maks. wiek skanu (min), 5-10080 |
| `health.token` | - | Token (ignored while `HEALTH_TOKEN` is set) |

## Deployment notes

- `HEALTH_TOKEN` (optional) - passed to the `app` service in
  `docker-compose.prod.yml` and frozen into `.env.local.php` by the entrypoint.
  Not needed when the token is set on the page.
- `HEALTH_CHECK_INTERVAL` (optional, scheduler service, minutes, default 15).
- `MAILER_DSN` must be set for e-mail alerts.
- The scheduler intervals are not needed by the app container: the expected
  interval of every job is inferred from the cron log.
