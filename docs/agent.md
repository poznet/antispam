# Maildir Agent

## Overview

The antispam agent is a standalone PHP script that runs directly on a hosting
server, operating on Maildir folders without IMAP. It keeps its rules,
settings and state in a local SQLite database. The panel talks to it over SSH
(`AntispamBundle\Services\SshService`); see [accounts.md](accounts.md).

Current version: **3.1** (`AGENT_VERSION` at the top of the script; also
returned as `agent_version` in every JSON answer). The panel compares it with
the bundled version and asks for a re-deploy (Konta → Wdróż) when the remote
agent is older or does not know a command.

## Requirements

- PHP **7.1+** (the script stays 7.1-compatible; it also runs on PHP 8.x)
- PHP extensions: **SQLite3** and **mbstring** (both required; `test` fails
  without them)
- Optional: **curl** (VirusTotal, Google Safe Browsing, CERT Polska list
  download), a reachable ClamAV daemon (`clamd`), DNS resolution for DNSBL /
  URI block lists (`dns_get_record`, falls back to `gethostbyname`)
- Write access to the agent directory (the database lives next to the script)
  and to the Maildir
- No Composer dependencies

## Installation

1. Use **Konta → Wdróż** (or `antispam:agent:deploy <id>`): the script is
   uploaded over SFTP (`~/` is resolved against the SFTP home directory),
   `test` is run against the account's Maildir and the account is marked
   deployed only when the upload and the self-test succeed. The panel then
   pushes rules and settings (Sync).
2. Or download `antispam-agent.php` (Konta → Pobierz agenta), copy it to e.g.
   `~/antispam-agent/` and run `import-rules` yourself.

## Output protocol

Every command prints exactly one JSON document on STDOUT. PHP warnings never
reach STDOUT (`display_errors` is switched off at start-up); they are collected
into a `warnings` array of the answer. Invalid UTF-8 (raw 8-bit headers) is
replaced with `?` before encoding. Fatal errors and uncaught exceptions still
produce `{"success": false, "error": "..."}`. Only the help text for an unknown
command is plain text; the panel recognises it as "agent too old".

## Database per account

`--account=<id>` selects `rules-<id>.sqlite` next to the script (the panel
always passes the account id), so two mailboxes of one SSH user no longer
share rules, settings or the "already checked" history. Without `--account`
(and without `--db`) the legacy shared `rules.sqlite` is used.

When `rules-<id>.sqlite` does not exist yet and `rules.sqlite` does, it is
seeded with a copy of the legacy database: the checked-message history
survives the upgrade, so mail already in INBOX is not scanned again. The next
Sync replaces the copied rules and settings with the account's own. The old
`rules.sqlite` can be deleted once every account on the host has been synced.

The database contains API keys (VirusTotal, Safe Browsing): it is created
`0600` and older `0644` files are tightened to `0600` when opened.
`--db=<path>` overrides the location (no `..`, `~/` is expanded).

## Commands

### test
```bash
php antispam-agent.php test --maildir=/home/user/Maildir
```
Checks PHP version, SQLite3, mbstring, curl, `dns_get_record`, the Maildir
(`new`, `cur`, writable) and that the agent directory is writable.
`success` is false (with `errors`) when something required is missing.

### version
```bash
php antispam-agent.php version
```
`{"success": true, "php": "8.2.1", "agent_version": "3.0"}`

### import-rules
```bash
php antispam-agent.php import-rules --account=5 < rules.json
```
Replaces all rules (and, when the payload has a `settings` section, all
settings) in **one transaction**: a malformed payload or a failed write keeps
the previous rules. Every list row must be an object with its key field
(`host`, `whitelistemail`, `blacklistemail`, `zone`).
Returns `{"success", "imported": {...counts}, "db": "rules-5.sqlite"}`.

The panel uploads the JSON over SFTP to a `0600` file
`<agent dir>/.rules-import-<random>.json`, runs
`import-rules < file` and deletes the file. There is no size limit and no
shell quoting of the JSON (the old `echo '<json>' |` transport broke on `\n`
inside rules and on payloads above 128 KiB). Agents older than 3.0 read stdin
the same way, so syncing to a not-yet-updated agent still works.

### scan
```bash
php antispam-agent.php scan --maildir=/home/user/Maildir --account=5
php antispam-agent.php scan --no-clamav --no-virustotal
```
Scans `new/` and `cur/`, moves spam to `.SPAM/` and suspicious mail to
`.QUARANTINE/`.

Flags: `--spam-threshold=N`, `--quarantine-threshold=N`, `--no-dnsbl`,
`--no-headers`, `--no-impersonation`, `--no-urls`, `--no-cert`,
`--no-attachment-policy`, `--no-clamav`, `--no-virustotal`. A `--no-*` flag
forces the check off even when it is enabled in the synced settings.

Thresholds and switches, in order of precedence: CLI flag → synced setting
(`spam_threshold`, `quarantine_threshold`, `scoring_enabled`, `dnsbl_enabled`,
`header_check_enabled`, ...) → default (10 / 5, the web defaults). The panel
passes the current thresholds and switches as flags on every scan, so a change
in Ustawienia applies before the next Sync, also on agents older than 3.0.
With `scoring_enabled` = 0 only the lists apply and a blacklist hit is spam,
like the web pipeline.

Pipeline (mirrors the web listeners): whitelist → blacklist → header
heuristics → impersonation / BEC → DNSBL → link protection → CERT list →
attachment policy → ClamAV / VirusTotal → decision. See
[scoring.md](scoring.md) and [protection.md](protection.md).

Behaviour details:

- **Sender** = the `From:` address only (not `Sender:`), taken from the last
  `<addr>` outside quoted strings / comments: `"ceo@firma.pl" <x@evil.com>`
  is `x@evil.com`. Headers are unfolded before parsing, so folded `From:`,
  `Subject:`, `Received:` and `Authentication-Results:` work.
- **List patterns** (exact / wildcard / regex) behave like `PatternMatcher`:
  regex patterns are not lower-cased (`\D` stays `\D`), matching is
  case-insensitive. Reasons are named like on the web
  (`blacklist:<pattern> (<type>)`, `email_blacklist:...`).
- **Headers**: only the topmost `Authentication-Results` / `Received-SPF`
  header counts. Defaults (same as `HeaderAnalyzer` on the web side):
  `spf_fail` 6, `dkim_fail` 4 (not when another signature passed),
  `dkim_none` 1, `dmarc_fail` 6, `dmarc_none` 1, `from_reply_mismatch` 3,
  `suspicious_subject` 3 (RFC 2047-decoded subject; also all-caps),
  `missing_message_id` 2, `many_received_hops` 2. Caps: the soft signals
  together stay below `quarantine_threshold` and the whole header score below
  `spam_threshold` (reason `header_cap` with the negative difference) - hard
  SPF/DKIM/DMARC failures can quarantine, headers alone never mean spam.
  Overridable with `header_<rule>_score`, `header_soft_cap` and
  `header_score_cap` settings. `AgentParityTest` compares the agent with
  `HeaderAnalyzer` on the same inputs.
- **DNSBL**: the IP is the first public address in the `from` clause of the `Received:` headers,
  topmost first (private / reserved hops skipped, like
  `RawMessageParser::getConnectingIp`). An answer counts as *listed* only in
  127.0.0.0/8, excluding 127.0.0.1 (query refused) and 127.255.255.0/24
  (Spamhaus error codes for public resolvers). Resolver errors and unusable
  answers (e.g. an ISP's NXDOMAIN hijack to a public IP) are not cached.
  The same rule applies to URI block lists.
- **Checked id** = file name cut at the first `:` (Dovecot keyword flags are
  lower-case letters, `:2,Sab`), so a flag change never re-scans a message.
  Ids stored by agents before 3.0 are still recognised.
- **Moves** are verified: a failed `rename()` is reported in `errors` and
  `move_failed`, the message is *not* marked checked and the move is retried
  on the next run. A file that went from `new/` to `cur/` meanwhile is found
  there and moved. New folders get `new/cur/tmp` (0700) and the Maildir++
  `maildirfolder` marker.
- **Locking**: `scan` and `apply-blacklist` hold an exclusive `flock` on
  `<db>.lock`; a second run returns `{"success": false, "locked": true}`.
- **Batched writes**: one SQLite transaction per 50 messages / 2 s.
- **ClamAV**: after a connection failure clamd is skipped for the rest of the
  run (no 30 s timeout per attachment).
- **Housekeeping** (at most daily, only after a scan that could read both
  INBOX directories): `score_log` rows older than `agent_retention_days`
  (default 180, min. 30), `dnsbl_cache` older than 7 days, `scan_log` beyond
  the last 1000 runs, and `checked` markers of files no longer in INBOX that
  are older than the retention period. Counts are returned in `pruned`.

Output:
```json
{
  "success": true,
  "total": 150, "checked": 120, "skipped": 30,
  "whitelisted": 45, "blacklisted": 12,
  "moved_to_spam": 12, "quarantined": 3, "move_failed": 0,
  "attachments_flagged": 2, "score_total": 410,
  "spam_threshold": 10, "quarantine_threshold": 5,
  "decisions": [{"file": "1700000001.M1P2.host", "decision": "spam", "score": 12}],
  "errors": [],
  "agent_version": "3.0"
}
```
`decisions` is capped at 200 entries (`decisions_truncated`), `errors` at 50.

### apply-blacklist
```bash
php antispam-agent.php apply-blacklist --spam-threshold=10 --days=30 --account=5
```
Retroactive pass used after a new blacklist rule is synced: INBOX files
(`new`, `cur`) modified in the last `--days` (default 30, at most `--limit`,
default 5000) whose `From:` matches a domain / e-mail blacklist rule worth at
least the spam threshold (any hit when scoring is off) are moved to `.SPAM`.
Only headers are read; whitelisted senders are skipped. Logged in `score_log`
as `spam` with the reason `retroactive …`. Returns `{"success", "examined",
"moved_to_spam", "move_failed", "truncated", "errors"}`. See
[spam-handling.md](spam-handling.md).

### health
```bash
php antispam-agent.php health --maildir=/home/user/Maildir --account=5
```
Version, database size, rule counts, last scan, attachment / protection
switches, message counts per folder.

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
names (everything before the first `:`). Anything other than `[A-Za-z0-9._,=-]` is
rejected, so an id can't escape the folder.

```bash
php antispam-agent.php quarantine-list [--since=<unix-ts>] [--limit=200]
```
Lists `.QUARANTINE/{new,cur}`, newest first, with sender, subject, date, size and
the score / reasons from `score_log` (matched via `score_log.file`). `--since`
filters by delivery time (file mtime). A message with raw 8-bit headers is
listed with `?` for the invalid bytes; an unreadable file is skipped and
reported in `errors` instead of hiding the whole list.

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

## SPAM folder (agent 3.1+)

Used by the user area **Spam** page (`/my/spam`, see [users.md](users.md)). Same id rules
as the quarantine commands.

```bash
php antispam-agent.php spam-list [--limit=100]
php antispam-agent.php spam-release --id=<id> [--whitelist]
```

`spam-list` lists `.SPAM/{new,cur}` newest first (file mtime). The folder can be large,
so only names and mtimes are collected first and headers are read for the newest
`--limit` files only (default 100, max 500); `total` is the number of files in the
folder. Items have the same shape as `quarantine-list` (`id`, `from`, `from_name`,
`subject`, `date`, `received_at`, `size`, `score`, `reasons`; score/reasons from
`score_log.file`, `null` / `[]` when unknown). A missing `.SPAM` folder gives an empty list.

`spam-release` moves the message from `.SPAM/new` or `.SPAM/cur` back to the same
sub-folder of INBOX (Maildir flags kept), marks it checked so the next scan leaves it
alone, and with `--whitelist` adds the sender to the local `email_whitelist` (the panel
adds the rule to its database too and syncs the rules afterwards). Answers
`{"success": true, "id": "...", "sender": "a@b.pl", "whitelisted": false}`; an id that is
not in `.SPAM` gives `{"success": false, "error": "Message not found in the SPAM folder ..."}`.

Agents older than 3.1 answer with the usage text; the panel then reports the agent as
outdated for that mailbox (redeploy: Konta → Wdróż). Nothing else changed in 3.1 - the
SQLite schema is the same, rules and the checked history are kept on redeploy.

## Maildir Structure

```
~/Maildir/
  new/          <- new unread messages
  cur/          <- read messages (flags after ":2,", e.g. :2,S or :2,Sab)
  .SPAM/
    maildirfolder
    new/        <- spam (new)
    cur/        <- spam (read)
  .QUARANTINE/
    maildirfolder
    new/        <- suspicious (score between quarantine and spam thresholds)
    cur/
```

## SQLite Schema

```sql
CREATE TABLE whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, host TEXT, pattern_type TEXT DEFAULT "exact");
CREATE TABLE email_whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, whitelistemail TEXT, pattern_type TEXT DEFAULT "exact");
CREATE TABLE blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, host TEXT, pattern_type TEXT DEFAULT "exact", score INTEGER DEFAULT 10);
CREATE TABLE email_blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, blacklistemail TEXT, pattern_type TEXT DEFAULT "exact", score INTEGER DEFAULT 10);
CREATE TABLE checked (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT UNIQUE, checked_ts INTEGER);
CREATE TABLE dnsbl_providers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, zone TEXT UNIQUE, score INTEGER DEFAULT 5,
                              enabled INTEGER DEFAULT 1, cache_ttl INTEGER DEFAULT 3600);
CREATE TABLE dnsbl_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, zone TEXT, listed INTEGER, checked_at TEXT, UNIQUE(ip, zone));
CREATE TABLE score_log (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, subject TEXT, score INTEGER,
                        decision TEXT, reasons TEXT, scored_at TEXT, file TEXT);   -- index on file
CREATE TABLE scan_log (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT, total INTEGER, checked INTEGER,
                       moved_to_spam INTEGER, quarantined INTEGER);
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE cert_domains (domain TEXT PRIMARY KEY);   -- CERT Polska list, fetched by the agent itself
CREATE TABLE cert_meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE agent_meta (key TEXT PRIMARY KEY, value TEXT);   -- e.g. last_prune_ts
```

Columns added over time (`pattern_type`, `score`, `score_log.file`,
`checked.checked_ts`) are created automatically on older databases.
`checked_ts` is NULL for rows written before 3.0. The `dnsbl_cache` table also
caches URI block list answers, with the domain stored in the `ip` column.

The `settings` table holds the scanning configuration synced from the web
app. An import with a `settings` section replaces the whole table; a key that
is missing falls back to the same default the web app uses:

- scoring: `scoring_enabled`, `spam_threshold`, `quarantine_threshold`,
  `dnsbl_enabled`, `header_check_enabled` (optional overrides:
  `header_<rule>_score`, `header_soft_cap`, `header_score_cap`)
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
- CERT Polska list: `cert_enabled`, `cert_score`, `cert_url` (HTTPS only,
  default `https://hole.cert.pl/domains/v2/domains.txt`; the domain list itself
  is not pushed: the agent downloads it daily, see
  [protection.md](protection.md#cert-polska-warning-list-cert_hole))
- attachment policy: `attachment_policy_enabled`, `attachment_blocked_extensions`
  (comma-separated), `attachment_blocked_score`, `attachment_double_ext_score`,
  `attachment_mismatch_score`, `attachment_macro_score`,
  `attachment_encrypted_score`
- housekeeping: `agent_retention_days` (default 180)

Impersonation, link and attachment-policy checks are **on** by default.

## Rules JSON Format

Built by `AgentRulesExporter` (`antispam:agent:sync`, Konta → Synchronizuj,
after Wdróż, and before a retroactive blacklist pass):

```json
{
  "whitelist": [
    {"email": "user@example.com", "host": "trusted-domain.com", "pattern_type": "exact"}
  ],
  "email_whitelist": [
    {"email": "user@example.com", "whitelistemail": "friend@example.com", "pattern_type": "exact"}
  ],
  "blacklist": [
    {"email": "user@example.com", "host": "*.spam-domain.com", "pattern_type": "wildcard", "score": 10}
  ],
  "email_blacklist": [
    {"email": "user@example.com", "blacklistemail": "^promo\\d+@", "pattern_type": "regex", "score": 6}
  ],
  "dnsbl": [
    {"name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "score": 5, "enabled": true, "cache_ttl": 3600}
  ],
  "settings": {
    "scoring_enabled": true,
    "spam_threshold": 10,
    "quarantine_threshold": 5,
    "dnsbl_enabled": true,
    "header_check_enabled": true,
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
    "cert_enabled": false,
    "cert_score": 10,
    "cert_url": "",
    "url_enabled": true,
    "url_dbl_zones": "dbl.spamhaus.org 6\nmulti.surbl.org 6",
    "attachment_policy_enabled": true,
    "attachment_blocked_extensions": "exe,scr,js,iso,lnk"
  }
}
```

`pattern_type` defaults to `exact`, `score` to 10 (blacklists) / 5 (DNSBL).
Booleans are stored as `1` / `0`.

## Compatibility notes (upgrading to 3.0)

- Re-deploy every SSH account (Konta → Wdróż). Until then the panel keeps
  working with the old agent: scans get the thresholds as flags, rules sync
  over the new SFTP transport, but answers carry an "agent outdated" warning
  and the old agent keeps its old behaviour (display-name sender, folded
  headers, unverified moves, shared `rules.sqlite`, DNSBL false positives).
- Deployments made with the default `~/antispam-agent` before this fix may
  have created a literal directory named `~` in the SSH user's home (SFTP does
  not expand `~`) while the agent was never reachable at the real path. Wdróż
  now uploads to the right place; the stray `~` directory can be removed.
- After the upgrade the first scan of a host seeds `rules-<id>.sqlite` from
  `rules.sqlite`; nothing is re-scanned.
