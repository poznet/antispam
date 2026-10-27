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
`--no-headers`, `--no-impersonation`, `--no-urls`, `--no-attachment-policy`,
`--no-clamav`, `--no-virustotal`. These flags force the respective check off even
when it is enabled in the synced settings.

The scan pipeline: whitelist → blacklist → header heuristics → impersonation /
BEC → DNSBL → link protection → attachment policy → ClamAV / VirusTotal →
decision. See [protection.md](protection.md) for the impersonation, link and
attachment-policy rules.

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

## Quarantine management

Used by the [quarantine digest](quarantine-digest.md). Message ids are Maildir base
names without the `:2,FLAGS` suffix. Anything other than `[A-Za-z0-9._,=-]` is
rejected, so an id can't escape the folder.

```bash
php antispam-agent.php quarantine-list [--since=<unix-ts>] [--limit=200]
```
Lists `.QUARANTINE/{new,cur}`, newest first, with sender, subject, date, size and
the score / reasons from `score_log` (matched via `score_log.file`). `--since`
filters by delivery time (file mtime).

```json
{"success": true, "total": 1, "items": [{"id": "1700000001.M1P2.host", "from": "x@evil.com",
  "from_name": "Jan Kowalski", "subject": "Pilny przelew", "date": "2026-10-26T10:00:00+01:00",
  "received_at": "2026-10-26T10:00:05+01:00", "size": 2048, "score": 8,
  "reasons": [{"rule": "impersonation_vip:Jan Kowalski", "score": 8}]}]}
```

```bash
php antispam-agent.php quarantine-release --id=<id> [--whitelist]
php antispam-agent.php quarantine-delete --id=<id>
```
`quarantine-release` moves the message back to `new/` or `cur/` (same sub-folder) and
marks it checked, so it is not quarantined again. `--whitelist` also adds the sender
to the local `email_whitelist`. The web app adds the same rule to its own database,
so the rule survives the next sync. `quarantine-delete` removes the file.

## Maildir Structure

```
~/Maildir/
  new/          <- new unread messages
  cur/          <- read messages (flags in filename, e.g. :2,S)
  .SPAM/
    new/        <- spam (new)
    cur/        <- spam (read)
  .QUARANTINE/
    new/        <- suspicious (score between quarantine and spam thresholds)
    cur/
```

## SQLite Schema

```sql
CREATE TABLE whitelist (id INTEGER PRIMARY KEY, email TEXT, host TEXT);
CREATE TABLE email_whitelist (id INTEGER PRIMARY KEY, email TEXT, whitelistemail TEXT);
CREATE TABLE blacklist (id INTEGER PRIMARY KEY, email TEXT, host TEXT);
CREATE TABLE email_blacklist (id INTEGER PRIMARY KEY, email TEXT, blacklistemail TEXT);
CREATE TABLE checked (id INTEGER PRIMARY KEY, message_id TEXT UNIQUE);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE score_log (id INTEGER PRIMARY KEY, sender TEXT, subject TEXT, score INTEGER,
                        decision TEXT, reasons TEXT, scored_at TEXT, file TEXT);
```

`score_log.file` (added in agent 2.2, created automatically on older databases)
links a decision to its Maildir file for the quarantine digest. The `dnsbl_cache`
table also caches URI block list answers, with the domain stored in the `ip` column.

The `settings` table holds scanning configuration synced from the web app:

- attachment scanning: `clamav_enabled`, `clamav_dsn`, `clamav_score`,
  `clamav_max_size`, `clamav_timeout`, `vt_enabled`, `vt_api_key`, `vt_score`,
  `vt_threshold`, `vt_timeout`
- impersonation: `impersonation_enabled`, `impersonation_protected_domains`
  (newline-separated, includes the account's own domain), `impersonation_vips`,
  `impersonation_vip_score`, `impersonation_lookalike_score`,
  `impersonation_embedded_score`, `impersonation_internal_score`
- links: `url_enabled`, `url_mismatch_score`, `url_ip_score`,
  `url_shortener_score`, `url_punycode_score`, `url_dbl_enabled`, `url_dbl_zones`
  (`zone score` per line), `url_max_domains`, `url_gsb_enabled`,
  `url_gsb_api_key`, `url_gsb_score`, `url_timeout`
- attachment policy: `attachment_policy_enabled`, `attachment_blocked_extensions`
  (comma-separated), `attachment_blocked_score`, `attachment_double_ext_score`,
  `attachment_mismatch_score`, `attachment_macro_score`,
  `attachment_encrypted_score`

A key missing from `settings` (agent never re-synced) falls back to the same
default the web app uses. Impersonation, link and attachment-policy checks are
**on** by default.

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
    "vt_timeout": 15,
    "impersonation_enabled": true,
    "impersonation_protected_domains": "firma.pl\nfirma.com",
    "impersonation_vips": "Jan Kowalski <jan@firma.pl>",
    "url_enabled": true,
    "url_dbl_zones": "dbl.spamhaus.org 6\nmulti.surbl.org 6",
    "attachment_policy_enabled": true,
    "attachment_blocked_extensions": "exe,scr,js,iso,lnk"
  }
}
```
