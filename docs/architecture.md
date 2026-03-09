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

Message filtering uses Symfony event dispatcher with prioritized listeners:

| Priority | Listener | Action |
|----------|----------|--------|
| 100000 | CheckIfIsAlreadyChecked | Skip if already processed |
| 99999 | CheckWhitelist | Domain whitelist check |
| 99998 | CheckEmailWhitelist | Email whitelist check |
| 99997 | CheckBlacklist | Domain blacklist check |
| 99996 | CheckEmailBlacklist | Email blacklist check |
| 99995 | MoveToSpam | Move to SPAM folder |
| -99999 | SetAsChecked | Mark as processed |

## Database

Four rule tables: `antispam_whitelist`, `antispam_email_whitelist`, `antispam_blacklist`, `antispam_email_blacklist`. Each stores email, host/address, and hit counter.

Account table: `antispam_account` - stores connection settings (IMAP or SSH) per email account.
