# Architecture

## Overview

Antispam is a Symfony 4.4 web application for filtering spam from email accounts. It supports two connection modes:

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
- Connects to mail server via IMAP protocol (port 143)
- Uses `ddeboer/imap` library
- Fetches messages, checks headers, moves spam to SPAM folder
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
| 99980    | CheckDnsbl             | DNSBL lookup against configured zones |
| 99970    | ApplyScoreDecision     | ham/quarantine/spam decision + log    |
| 99960    | MoveToSpam             | Physically move spam to SPAM folder   |
| -99999   | SetAsChecked           | Mark as processed                     |

See `scoring.md` for scoring thresholds, pattern types and DNSBL configuration.

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

Account table: `antispam_account` - stores connection settings (IMAP or SSH) per email account.
