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
| 99970    | ApplyScoreDecision     | ham/quarantine/spam decision + log    |
| 99965    | RecordSpamSignals      | Record fingerprints of detected spam  |
| 99960    | MoveToSpam             | Move spam to SPAM (or delete it)      |
| -99999   | SetAsChecked           | Mark as processed                     |

(Attachment listeners `CheckAttachments` (99975) and `CheckAttachmentsVirusTotal`
(99973) run between DNSBL and the decision when enabled.)

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
- `antispam_cron_run` — runs of periodic commands started through
  `antispam:cron:run` (command, start/end, exit code, output), kept 14 days.
  See `spam-handling.md`.

Account table: `antispam_account` - stores connection settings (IMAP or SSH) per email account.
