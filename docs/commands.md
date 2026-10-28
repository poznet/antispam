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

## Cron Log

### antispam:cron:run
Runs another `antispam:*` command and stores the run (start/end, exit code,
output) in the cron log shown on **Przegląd → Logi crona**. Use it in crontab
and the Docker scheduler. See [spam-handling.md](spam-handling.md).
```bash
php bin/console antispam:cron:run antispam:agent:scan-all
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
error saved in `cert.last_error`). Run by the scheduler every `CERT_SYNC_INTERVAL` hours.

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
