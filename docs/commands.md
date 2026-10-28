# CLI Commands

## Existing Commands

### antispam:check
Validates email account configuration.
```bash
php bin/console antispam:check
```

### antispam:go
Runs spam filtering on INBOX of the legacy mailbox from Ustawienia → E-mail
(also included in `antispam:agent:scan-all`).
```bash
php bin/console antispam:go
```

## Agent Commands

### antispam:agent:deploy
Deploys the agent script to a hosting server via SSH.
```bash
php bin/console antispam:agent:deploy {accountId}
```

### antispam:agent:sync
Syncs blacklist/whitelist rules to the remote agent's SQLite database.
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
```bash
php bin/console antispam:agent:scan-all
```

## Rules

### antispam:rules:make-global
Turns the white/black list rules of one mailbox into global rules
("Wszystkie skrzynki", owner `*`, see [scoring.md](scoring.md#rule-ownership)).
For installs from the single-mailbox days, where every panel rule belonged to
the legacy mailbox from the "E-mail" settings and never reached IMAP/SSH accounts.
A rule that already exists globally is removed and its hit counter added to
the global one. SSH agents need a sync afterwards.
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
```

### antispam:purge
Housekeeping, run daily (the Docker scheduler does it at `PURGE_HOUR`:41):
deletes score log rows (`antispam_spam_score_log`) older than the retention and
DNSBL cache rows (`antispam_dnsbl_cache`) older than the longest provider cache
TTL (at least 24 h). Retention comes from the config key
`scorelog.retention_days` (default 180; `0` = keep the score log forever). There
is no panel field yet - set it with `--days` per run or in the `config` table.
```bash
php bin/console antispam:purge
php bin/console antispam:purge --days=90     # override the retention for this run
php bin/console antispam:purge --dry-run     # only count
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
php bin/console antispam:digest:send --force              # send even if disabled in settings
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
with a remote hub configured (**Settings → Shared Spam Feed**). See
[feed.md](feed.md).
```bash
php bin/console antispam:feed:sync
php bin/console antispam:feed:sync --push-only
php bin/console antispam:feed:sync --pull-only
```
