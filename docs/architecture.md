# Architecture

## Overview

Antispam is a Symfony 7.4 web application for filtering spam from email accounts. It supports two connection modes:

```
[Symfony Web App]                    [Hosting Server]
├── Account management               ├── antispam-agent.php
│   ├── IMAP mode (ddeboer/imap)     ├── rules.sqlite
│   └── SSH mode (phpseclib)         ├── ~/Maildir/{new,cur}/
├── Blacklist/Whitelist rules        └── ~/Maildir/.SPAM/{new,cur}/
├── Event-driven filtering pipeline
└── CLI commands (scan, deploy, sync)
```

## Connection Modes

### IMAP Mode
- Connects to mail server via IMAP protocol (port 993 / SSL by default, configurable)
- Uses `ddeboer/imap` library
- Fetches messages, checks headers, moves spam to SPAM folder
- `ImapScanService` runs the pipeline for IMAP accounts and the legacy mailbox
  (Ustawienia → Konfiguracja (stara)); `MessageEvent` carries the message's own connection
- All processing happens on the Symfony server

#### Incremental INBOX scan

Each IMAP mailbox keeps a **UID cursor**: INBOX `UIDVALIDITY` + the highest
UID already run through the pipeline (`antispam_account.imap_uid_validity` /
`imap_last_uid`; the legacy mailbox uses the config key `imap.legacy_cursor`,
`"uidvalidity:last_uid:unix time"`). A scan picks its messages like this:

| Situation | Messages scanned |
|-----------|------------------|
| cursor valid (normal case) | only UIDs above the cursor (`UID FETCH n:*`) |
| first scan of a new mailbox (`lastScanAt` null; legacy: no cursor and no markers) | the whole INBOX (initial clean-up, kept out of stats) |
| cursor `0/0` - set by *Zresetuj flagi sprawdzenia* (`/config/uncheck-all/`) | the whole INBOX once |
| no cursor but scanned before (upgrade from a version without cursors), or `UIDVALIDITY` changed, or the IMAP host/port/login was edited | only mail received since the last scan minus one day (`SEARCH SINCE`; legacy mailbox: 4 days) - **older mail is never touched** |
| server reports no `UIDVALIDITY` | "since the last scan" every time, no cursor |

The cursor advances to the highest UID processed; when a message throws
(e.g. a failed move) it stays just below that UID, so the message is retried
on the next run (messages above it are skipped by their markers). In a
"since" pass the cursor jumps past everything that existed when the pass
started, failures included, because mail above a failed UID may be old.
`total` in a scan result is the INBOX size, `checked` the new messages.

**Markers** (`MessageService`, `var/data/checked/v2/<2 hex>/<sha1>`) record
processed messages per mailbox: sha1(account e-mail + Message-ID), or of the
raw header block for mail without a Message-ID (such mail used to be treated
as "already checked" and was never filtered). They are needed only above the
cursor (mail released from quarantine re-enters INBOX with a new UID, retried
failures), so markers older than 90 days are purged once a day after a scan
(`MessageService::purgeIfDue()`). Pre-v2 markers (file named after the
Message-ID, valid for every mailbox) are still honoured until purged.

**Robustness:** every IMAP connection gets c-client timeouts (open 20 s,
read/write 60 s, `ImapScanService::applyImapTimeouts()`); a mailbox is
scanned by one process at a time (`flock` on `var/data/locks/imap-scan-*.lock`,
a second scan gets `ScanLockedException` "Skanowanie tej skrzynki już trwa" -
scan-all skips the mailbox, a panel scan job waits and retries); a scan can be
limited to a deadline / message count and continues from the cursor next time
(background scan jobs in batches, scan-all `SCAN_MAX_SECONDS`, [jobs.md](jobs.md)); a failed flush
that closes the EntityManager is reset after the message, so one bad message
does not fail the rest of the run; each message's score-log row is detached
from the unit of work after processing.

### SSH+Maildir Mode
- Connects to hosting server via SSH (phpseclib)
- Deploys a standalone PHP agent script
- Agent operates directly on Maildir folders (filesystem)
- Rules synced from main app to local SQLite database
- Faster, no IMAP overhead, works on shared hosting

## Event Pipeline

Message filtering uses Symfony event dispatcher with prioritized listeners.
Whitelist hits short-circuit. Blacklist / header / DNSBL steps accumulate a
spam score; the final decision listener turns the score into
ham/quarantine/spam.

| Priority | Listener               | Action                                |
|----------|------------------------|---------------------------------------|
| 100000   | CheckIfIsAlreadyChecked| Skip if already processed             |
| 99999    | CheckWhitelist         | Domain whitelist (short-circuit)      |
| 99998    | CheckEmailWhitelist    | Email whitelist (short-circuit)       |
| 99997    | CheckBlacklist         | Domain blacklist → add score          |
| 99996    | CheckEmailBlacklist    | Email blacklist → add score           |
| 99990    | CheckHeaders           | SPF/DKIM/DMARC + heuristics           |
| 99988    | CheckImpersonation     | VIP spoofing, lookalike domains, BEC  |
| 99980    | CheckDnsbl             | DNSBL lookup against configured zones |
| 99979    | CheckUrls              | Link heuristics, URI DBL, Safe Browsing |
| 99978    | CheckSharedFeed        | Match sender/body against shared feed |
| 99976    | CheckAttachmentPolicy  | Blocked types, double ext., macros    |
| 99972    | CheckBayes             | Local learned classifier (opt-in, `bayes.md`) |
| 99970    | ApplyScoreDecision     | ham/quarantine/spam decision + log    |
| 99965    | RecordSpamSignals      | Record fingerprints of detected spam  |
| 99960    | MoveToSpam             | Move spam to SPAM (or delete it)      |
| -99999   | SetAsChecked           | Mark as processed                     |

(Attachment listeners `CheckAttachments` (99975) and `CheckAttachmentsVirusTotal`
(99973) run between DNSBL and the decision when enabled. The order is pinned by
`MessagePipelineTest::testListenerOrder`.)

All white/blacklists match the **From:** address (domain lists: its domain),
the same address the score log, impersonation check, retroactive pass and
plugin scanner use - not the `Sender:` header, which a spammer could set to a
whitelisted domain. Rule hit counters are incremented in SQL
(`counter = counter + 1`), so parallel scans do not lose hits.

`CheckHeaders`, `CheckDnsbl` and `CheckImpersonation` read the **raw header
block** (`imap_fetchheader`, one fetch per message): `imap_headerinfo()` has no
`Received`, `Authentication-Results` or `Received-SPF` lines, so before this
SPF/DKIM/DMARC, the own-domain spoof check and DNSBL never fired for IMAP.

A failed move to `QUARANTINE` is rethrown by `ApplyScoreDecision` (like a
failed move to `SPAM` in `MoveToSpam`): the message is not marked as checked,
the cursor stays below it and the next scan tries again.

See `scoring.md` for scoring thresholds, pattern types and DNSBL configuration,
`protection.md` for impersonation / link / attachment-policy rules, and `feed.md`
for the shared spam feed.

## Quarantine digest

`antispam:digest:send` (cron) e-mails each mailbox owner the newly quarantined
messages with signed one-click links to `/q/{token}` (public, POST-to-act). Both
quarantine back-ends sit behind `QuarantineService`: the IMAP `QUARANTINE` folder
and the agent's `quarantine-list` / `quarantine-release` / `quarantine-delete`
commands. See `quarantine-digest.md`.

## Spam handling, retroactive rules, cron log

Where spam goes (move vs delete), what quarantine means, how a new blacklist
rule clears mail already in INBOX (`RetroactiveSpamService`, agent
`apply-blacklist`) and the cron log (`antispam:cron:run`, `/cron/logs`) are
described in `spam-handling.md`.

## Database

Rule tables: `antispam_whitelist`, `antispam_email_whitelist`,
`antispam_blacklist`, `antispam_email_blacklist`. Each stores email,
host/address, a `pattern_type` (`exact`/`wildcard`/`regex`) and hit counter.
Blacklist rows additionally carry a per-rule `score`.

Additional tables:
- `antispam_dnsbl_provider` — configured DNS block list zones (name, zone,
  score, cache_ttl, enabled, hits).
- `antispam_dnsbl_cache` — per-IP DNSBL lookup results, TTL-capped.
- `antispam_spam_score_log` — per-message decision log with score, reasons
  (JSON), decision (ham/quarantine/spam/whitelisted) and timestamp.
- `antispam_shared_spam_signal` — shared spam feed fingerprints: `type`
  (sender/body), SHA-256 `hash`, `origin` (local/remote) and `reports` count.
  See `feed.md`.
- `antispam_list_setting` — long list-shaped settings (protected domains, VIPs,
  URI block list zones, blocked extensions) that don't fit the config table's
  255-character values. See `protection.md`.
- `antispam_bayes_token`, `antispam_bayes_message` — hashed token counts and
  learned-message fingerprints of the optional Bayes classifier. See `bayes.md`.
- `antispam_job` — background job queue (heavy panel operations run by
  `antispam:jobs:work`): type, payload, status, progress, result, dedupe key.
  See `jobs.md`.
- `antispam_cron_run` — runs of periodic commands started through
  `antispam:cron:run` (command, start/end, exit code, output), kept 14 days.
  See `spam-handling.md`.

Account table: `antispam_account` - stores connection settings (IMAP or SSH) per email account.
