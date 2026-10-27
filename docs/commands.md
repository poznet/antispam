# CLI Commands

## Existing Commands

### antispam:check
Validates email account configuration.
```bash
php app/console antispam:check
```

### antispam:go
Runs spam filtering on INBOX via IMAP (legacy single-account mode).
```bash
php app/console antispam:go
```

## Agent Commands

### antispam:agent:deploy
Deploys the agent script to a hosting server via SSH.
```bash
php app/console antispam:agent:deploy {accountId}
```

### antispam:agent:sync
Syncs blacklist/whitelist rules to the remote agent's SQLite database.
```bash
php app/console antispam:agent:sync {accountId}
```

### antispam:agent:scan
Runs a spam scan on a single account (works for both IMAP and SSH modes).
```bash
php app/console antispam:agent:scan {accountId}
```

### antispam:agent:scan-all
Scans all configured accounts. Suitable for cron.
```bash
php app/console antispam:agent:scan-all
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
php bin/console antispam:digest:send --mailbox=ssh-3      # one mailbox ("imap" or "ssh-<accountId>")
php bin/console antispam:digest:send --since="-3 days"    # ignore the last-sent marker
php bin/console antispam:digest:send --force              # send even if disabled in settings
```

## Shared Feed Commands

### antispam:feed:sync
Pushes locally detected spam fingerprints to the configured shared-feed hub and
pulls everyone else's. Suitable for cron. Requires the shared feed to be enabled
with a remote hub configured (**Settings → Shared Spam Feed**). See
[feed.md](feed.md).
```bash
php app/console antispam:feed:sync
php app/console antispam:feed:sync --push-only
php app/console antispam:feed:sync --pull-only
```
