# CLI Commands

## Existing Commands

### antispam:check
Validates email account configuration.
```bash
php bin/console antispam:check
```

### antispam:go
Runs spam filtering on INBOX of the legacy mailbox from Ustawienia → Konfiguracja (stara)
(also included in `antispam:agent:scan-all`).
```bash
php bin/console antispam:go
```

## Agent Commands

### antispam:agent:deploy
Deploys the agent script to a hosting server via SSH and runs its self-test;
exits 1 (and leaves the account "not deployed") when the upload or the test
fails. Run `antispam:agent:sync` afterwards to push rules and settings.
```bash
php bin/console antispam:agent:deploy {accountId}
```

### antispam:agent:sync
Syncs blacklist/whitelist rules, DNSBL providers and scanning settings to the
remote agent's per-account SQLite database; exits 1 when the agent rejects the
import.
```bash
php bin/console antispam:agent:sync {accountId}
```

### antispam:agent:scan
Runs a spam scan on a single account (works for both IMAP and SSH modes).
```bash
php bin/console antispam:agent:scan {accountId}
```

### antispam:agent:scan-all
Scans every mailbox: SSH accounts with a deployed agent, IMAP accounts and the
legacy mailbox (if configured). Prints per-mailbox counters (new, spam,
quarantine, whitelisted) and per-message errors. Exits non-zero when any
mailbox failed. Suitable for cron.

A mailbox being scanned by another process (a panel scan job, the agent's own
lock) or with an active panel scan job is **skipped**, not counted as a
failure. Each IMAP mailbox gets at most `--max-seconds` per run (default env
`SCAN_MAX_SECONDS` or 600, `0` = no limit); the rest of a huge INBOX is scanned
on the next run from the cursor ("N left for the next run"). See [jobs.md](jobs.md).
```bash
php bin/console antispam:agent:scan-all
php bin/console antispam:agent:scan-all --max-seconds=0   # no per-mailbox limit
```

### antispam:rescan:due
Queues the weekly full rescans that are due: accounts with **Cotygodniowy
ponowny skan całej skrzynki** on, whose slot of this week (day + hour, server
time; default Sunday 02:00) started less than 24 h ago and that had no rescan
since. Only queues `account.rescan` jobs (deduplicated per account) - the job
worker runs them. Run it hourly; the Docker scheduler does at minute 7
(`RESCAN_DUE=off` disables it). See [spam-handling.md](spam-handling.md#full-rescan).
```bash
php bin/console antispam:cron:run antispam:rescan:due
php bin/console antispam:rescan:due --dry-run       # list the due accounts
php bin/console antispam:rescan:due --account=12    # queue a rescan of one account now
```

## Background Jobs

### antispam:jobs:work (alias antispam:jobs:run)
Runs the jobs queued by the panel (scan, full rescan, agent deploy / sync / health,
retroactive rule pass, CERT sync, digest "send now", bulk phishing forward,
full health check). Loops and polls every 2 s; recovers jobs whose worker
died; every job gets a time limit. See [jobs.md](jobs.md).
```bash
php bin/console antispam:jobs:work --time-limit=3600   # long-running (Docker scheduler, systemd)
php bin/console antispam:jobs:run --once                # crontab: * * * * *
```
Options: `--once`, `--time-limit=N` (stop starting jobs after N s), `--memory-limit=256`,
`--sleep=2`, `--job-timeout=N` (env `JOBS_JOB_TIMEOUT`, default 3900), `--batch-seconds=N`
(env `JOBS_BATCH_SECONDS`, default 120 - length of one IMAP scan batch).

## Rules

### antispam:rules:make-global
Turns the white/black list rules of one mailbox into global rules
("Wszystkie skrzynki", owner `*`, see [scoring.md](scoring.md#rule-ownership)).
For installs from the single-mailbox days, where every panel rule belonged to
the legacy mailbox from the "E-mail" settings and never reached IMAP/SSH accounts.
A rule that already exists globally is removed and its hit counter added to
the global one (also when two copies of a value are in the batch). Same logic
as the panel action **Zmień na: Wszystkie skrzynki** (`RuleGlobalizer`,
[scoring.md](scoring.md#making-a-rule-global)), but without per-rule audit
entries or jobs: SSH agents need a sync afterwards.
```bash
php bin/console antispam:rules:make-global --dry-run          # preview
php bin/console antispam:rules:make-global                    # legacy mailbox
php bin/console antispam:rules:make-global --owner=jan@firma.pl
php bin/console antispam:agent:sync                           # push to SSH agents
```

## Cron Log

### antispam:cron:run
Runs another `antispam:*` command and stores the run (start/end, exit code,
output) in the cron log shown on **Przegląd → Logi crona**. Use it in crontab
and the Docker scheduler. See [spam-handling.md](spam-handling.md).
```bash
php bin/console antispam:cron:run antispam:agent:scan-all
php bin/console antispam:cron:run antispam:digest:send -- --scheduled-only   # options after "--"
```

### antispam:purge
Housekeeping, run daily (the Docker scheduler does it at `PURGE_HOUR`:41):
deletes score log rows (`antispam_spam_score_log`) older than the retention and
DNSBL cache rows (`antispam_dnsbl_cache`) older than the longest provider cache
TTL (at least 24 h). Retention comes from the config key
`scorelog.retention_days` (default 180; `0` = keep the score log forever). There
is no panel field yet - set it with `--days` per run or in the `config` table.
Audit log rows (`antispam_audit_log`) older than `audit.retention_days` (default
365, `0` = forever; not affected by `--days`) are deleted too, see [audit.md](audit.md).
Finished background jobs (`antispam_job`) older than `jobs.retention_days`
(default 30, `0` = forever) are deleted, queued / running ones never ([jobs.md](jobs.md#retention)).
The Bayes classifier's old fingerprints, rare stale tokens and rows of deleted
mailboxes go as well (own retention, skipped with `--dry-run`, see [bayes.md](bayes.md#storage-and-housekeeping)).
```bash
php bin/console antispam:purge
php bin/console antispam:purge --days=90     # override the retention for this run
php bin/console antispam:purge --dry-run     # only count
```

## Bayes Classifier

### antispam:bayes:train
Bootstraps the local Bayes classifier from IMAP folders: the newest `--limit`
(default 500, max 5000) messages of `--folder` (default `SPAM`) are learned as
spam, those of `--ham-folder` as ham. Read-only (flags unchanged, nothing
moved); works while the classifier is switched off. IMAP accounts and the
legacy mailbox only. See [bayes.md](bayes.md#bootstrap).
```bash
php bin/console antispam:bayes:train --account=jan@firma.pl --folder=SPAM --ham-folder=INBOX --limit=500
php bin/console antispam:bayes:train --legacy --folder=SPAM --ham-folder=INBOX
```

## Quarantine Digest Commands

### antispam:digest:send
Sends the [quarantine digest](quarantine-digest.md): one e-mail per mailbox with
messages quarantined since the previous digest, with signed one-click
deliver / always-accept / delete links. Mailboxes with nothing new are skipped.
Suitable for cron. Exits non-zero when any digest failed.
```bash
php bin/console antispam:digest:send
php bin/console antispam:digest:send --dry-run            # build and count, don't send
php bin/console antispam:digest:send --mailbox=ssh-3      # one mailbox ("imap", "imap-<accountId>" or "ssh-<accountId>")
php bin/console antispam:digest:send --since="-3 days"    # ignore the last-sent marker
php bin/console antispam:digest:send --force              # send even if disabled in settings (not to mailboxes switched off on their own)
php bin/console antispam:digest:send --scheduled-only     # hourly: only mailboxes with their own send hour that are due
```
Per-mailbox settings (account form, **Ustawienia skrzynki**) are honoured:
a mailbox switched off is reported as `disabled`, one with its own send hour
that is not due as `not-due`. `--mailbox` sends that mailbox regardless of its
hour. The command runs when the global digest is off but some mailbox has it
switched on. See [quarantine-digest.md](quarantine-digest.md#per-mailbox-settings).

## Phishing Forward

### antispam:phishing:forward

Automatic mode of the phishing forward to CERT Polska / SOC (see
[phishing.md](phishing.md#forwarding-to-cert-polska--soc)): sends reports older than the configured
delay that are not marked as false positive, at most 20 per run. Does nothing while the automatic mode
is off (the default). The Docker scheduler runs it every `PHISHING_FORWARD_INTERVAL` minutes (default 10).

```bash
php bin/console antispam:phishing:forward
```

## CERT Polska List

### antispam:cert:sync

Downloads the CERT Polska "Lista Ostrzeżeń" (`https://hole.cert.pl/domains/v2/domains.txt`)
into `antispam_cert_domain` and records the status (see
[protection.md](protection.md#cert-polska-warning-list-cert_hole)). Does nothing (exit 0)
while the filter is disabled in the panel; `--force` syncs anyway. Refuses to replace
the table when the download is empty or less than half of the current list (exit 1,
error saved in `cert.last_error`, clipped to 1000 characters). Any failure - also one
while saving the status - ends with exit 1 and the error in the output (cron log),
never with an uncaught exception. Run by the scheduler every `CERT_SYNC_INTERVAL` hours.

```bash
php bin/console antispam:cert:sync
php bin/console antispam:cert:sync --force
```

## Shared Feed Commands

### antispam:feed:sync
Pushes locally detected spam fingerprints to the configured shared-feed hub and
pulls everyone else's. Suitable for cron. Requires the shared feed to be enabled
with a remote hub configured (**Ustawienia → Wspólna baza spamu**). See
[feed.md](feed.md).
```bash
php bin/console antispam:feed:sync
php bin/console antispam:feed:sync --push-only
php bin/console antispam:feed:sync --pull-only
```

## Database

### antispam:db:upgrade
Creates or upgrades the schema with Doctrine Migrations; the Docker entrypoint runs it
at boot (`RUN_MIGRATIONS=true`). Empty database -> all migrations; install made by the
old `doctrine:schema:update` boot -> `schema:update` once (unknown tables are never
dropped) and every migration recorded as executed; migrated -> pending migrations.
Idempotent, serialized with a MySQL named lock (`--lock-timeout`, default 600 s).
Exit `0` up to date, `1` failed, `2` done with warnings (entity change without a
migration, or migrations in the database this release does not ship). See
[migrations.md](migrations.md).
```bash
php bin/console antispam:db:upgrade --dry-run   # state and plan, changes nothing
php bin/console antispam:db:upgrade
```
The plain Doctrine commands work too: `doctrine:migrations:status`,
`doctrine:migrations:list`, `doctrine:migrations:diff` (new migration, see
[migrations.md](migrations.md#adding-a-migration-developers)).

## Backup / Diagnostics

See [backup.md](backup.md) for the file format, secrets handling and the panel page
(**Ustawienia → Kopia zapasowa**).

### antispam:export
Writes the configuration (settings, list rules, DNSBL providers, accounts, users -
no quarantine, logs or phishing reports) as one versioned JSON, or a ZIP holding it.
Secrets only with `--include-secrets`, and then encrypted with the instance key
(derived from `APP_SECRET`).
```bash
php bin/console antispam:export --output=backup.json
php bin/console antispam:export --output=backup.zip --include-secrets
php bin/console antispam:export > backup.json        # stdout
```

### antispam:import
Restores such a file: validates the schema version, matches records by natural keys
(rule owner + value + type, DNSBL zone, account e-mail, username), never overwrites
secrets with empty values, runs in one transaction and prints a per-section summary.
```bash
php bin/console antispam:import backup.json --dry-run
php bin/console antispam:import backup.json                      # merge (default)
php bin/console antispam:import backup.json --only=rules,dnsbl
php bin/console antispam:import backup.json --mode=replace --confirm-replace
```

### antispam:doctor
Configuration sanity checks (APP_SECRET, encryption, mailer, https / proxies, public
URL, pending migrations / schema drift, cron, accounts, SSH agent versions, plaintext passwords, orphaned
rules, feed keys, ClamAV, PHP extensions, var/ permissions, disk space). Exit 1 when
a check fails; `--strict` also fails on warnings; `--format=json` for scripts.
```bash
php bin/console antispam:doctor
php bin/console antispam:doctor --strict
```

## Mail Client Plugins

### antispam:plugin:build

Builds the Thunderbird `.xpi` to a file (reproducible: same source + URL =
same bytes). See [plugin-distribution.md](plugin-distribution.md).

```bash
php bin/console antispam:plugin:build --generic            # no server URL, for addons.thunderbird.net
php bin/console antispam:plugin:build                      # instance build with plugin.public_url
php bin/console antispam:plugin:build --server=https://antispam.example.pl -o /tmp/tb.xpi
```

Default output: `build/antispam-thunderbird-<version>[-instance].xpi`; prints
the path and sha256. `bin/build-thunderbird-xpi --generic|--server=URL
[--output=FILE]` does the same without booting Symfony (no database, used by
CI).
