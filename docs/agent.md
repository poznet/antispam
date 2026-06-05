# Maildir Agent

## Overview

The antispam agent is a standalone PHP script that runs directly on a hosting server, operating on Maildir folders without IMAP. It uses SQLite for storing filtering rules.

## Requirements

- PHP 7.1+ with SQLite3 extension
- Access to Maildir directory structure
- No Composer dependencies required
- Optional: a reachable ClamAV daemon (`clamd`) for malware scanning, and the
  PHP `curl` extension for VirusTotal lookups. Both stay off unless enabled in
  the synced settings.

## Installation

1. Download `antispam-agent.php` from the web interface (Accounts > Download Agent)
2. Upload to your hosting server (e.g., `~/antispam-agent/`)
3. Or use automatic deploy from the web interface

## Commands

### Test environment
```bash
php antispam-agent.php test
```
Checks PHP version, SQLite3 extension, Maildir path, write permissions. Returns JSON.

### Import rules
```bash
echo '{"whitelist":[...],"blacklist":[...]}' | php antispam-agent.php import-rules
# or
php antispam-agent.php import-rules < rules.json
```
Imports filtering rules from JSON into local SQLite database.

### Scan mailbox
```bash
php antispam-agent.php scan
php antispam-agent.php scan --maildir=/home/user/Maildir
php antispam-agent.php scan --db=/home/user/antispam-agent/rules.sqlite
php antispam-agent.php scan --no-clamav --no-virustotal
```
Scans Maildir for spam and moves matching messages to `.SPAM/` folder.

Flags: `--spam-threshold=N`, `--quarantine-threshold=N`, `--no-dnsbl`,
`--no-headers`, `--no-clamav`, `--no-virustotal`. The attachment-scanning flags
force the respective check off even when it is enabled in the synced settings.

Output (JSON):
```json
{
  "total": 150,
  "checked": 120,
  "skipped": 30,
  "whitelisted": 45,
  "blacklisted": 12,
  "attachments_flagged": 2,
  "moved_to_spam": 12
}
```

## Attachment scanning

When enabled (via the synced settings — see below), the agent parses each
message's MIME structure, extracts attachment parts, and:

- **ClamAV** — streams each attachment to `clamd` via INSTREAM. A malware hit
  forces a spam decision and adds `clamav_score`.
- **VirusTotal** — looks up each attachment's SHA-256 (only the hash is sent,
  never the file). When the number of engines flagging the file as malicious
  reaches `vt_threshold`, it forces a spam decision and adds `vt_score`.

Both are best-effort: an unreachable `clamd`, a missing `curl` extension, an
unknown hash, or a VirusTotal rate limit never condemns a legitimate message.
The matched verdict is recorded in `score_log.reasons` as `clamav:<signature>`
or `virustotal:<malicious>/<total>`.

These settings are configured in the web UI (**Settings → Spam Filter
Settings**) and pushed to the agent in the `settings` section of the
`import-rules` payload (Accounts → Sync, or `antispam:agent:sync`).

## Maildir Structure

```
~/Maildir/
  new/          <- new unread messages
  cur/          <- read messages (flags in filename, e.g. :2,S)
  .SPAM/
    new/        <- spam (new)
    cur/        <- spam (read)
```

## SQLite Schema

```sql
CREATE TABLE whitelist (id INTEGER PRIMARY KEY, email TEXT, host TEXT);
CREATE TABLE email_whitelist (id INTEGER PRIMARY KEY, email TEXT, whitelistemail TEXT);
CREATE TABLE blacklist (id INTEGER PRIMARY KEY, email TEXT, host TEXT);
CREATE TABLE email_blacklist (id INTEGER PRIMARY KEY, email TEXT, blacklistemail TEXT);
CREATE TABLE checked (id INTEGER PRIMARY KEY, message_id TEXT UNIQUE);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
```

The `settings` table holds attachment-scanning configuration synced from the
web app: `clamav_enabled`, `clamav_dsn`, `clamav_score`, `clamav_max_size`,
`clamav_timeout`, `vt_enabled`, `vt_api_key`, `vt_score`, `vt_threshold`,
`vt_timeout`.

## Rules JSON Format

```json
{
  "whitelist": [
    {"email": "user@example.com", "host": "trusted-domain.com"}
  ],
  "email_whitelist": [
    {"email": "user@example.com", "whitelistemail": "friend@example.com"}
  ],
  "blacklist": [
    {"email": "user@example.com", "host": "spam-domain.com"}
  ],
  "email_blacklist": [
    {"email": "user@example.com", "blacklistemail": "spammer@example.com"}
  ],
  "settings": {
    "clamav_enabled": true,
    "clamav_dsn": "tcp://127.0.0.1:3310",
    "clamav_score": 15,
    "clamav_max_size": 26214400,
    "clamav_timeout": 30,
    "vt_enabled": false,
    "vt_api_key": "",
    "vt_score": 15,
    "vt_threshold": 3,
    "vt_timeout": 15
  }
}
```
