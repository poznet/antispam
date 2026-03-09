# CLI Commands

## Existing Commands

### antispam:check
Validates email account configuration.
```bash
php bin/console antispam:check
```

### antispam:go
Runs spam filtering on INBOX via IMAP (legacy single-account mode).
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
Scans all configured accounts. Suitable for cron.
```bash
php bin/console antispam:agent:scan-all
```
