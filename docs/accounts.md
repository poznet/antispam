# Account Management

## Overview

Each email account can be configured with one of two connection modes: IMAP or SSH+Maildir.

## IMAP Mode

Traditional mode using IMAP protocol to connect to mail server.

**Configuration fields:**
- **Email** - email address
- **IMAP Host** - mail server hostname
- **IMAP Port** - default 143
- **Login** - IMAP username
- **Password** - IMAP password
- **IMAP Flags** - connection flags (default: `/novalidate-cert/notls`)

## SSH+Maildir Mode

Direct access to Maildir on hosting server via SSH.

**Configuration fields:**
- **Email** - email address
- **SSH Host** - hosting server hostname
- **SSH Port** - default 22
- **SSH User** - SSH username
- **SSH Key Path** - path to private key file on Symfony server
- **Maildir Path** - path to Maildir on hosting (default: `~/Maildir`)
- **Agent Path** - where to deploy agent (default: `~/antispam-agent`)

## SSH Key Setup

1. Generate SSH key pair: `ssh-keygen -t ed25519 -f /path/to/key -N ""`
2. Add public key to hosting's `~/.ssh/authorized_keys`
3. Set key path in account configuration

## Operations (SSH mode)

### Test Connection
Verifies SSH connectivity and checks remote environment (PHP, SQLite3, Maildir).

### Deploy Agent
Uploads `antispam-agent.php` to the hosting server and runs environment test.

### Sync Rules
Exports all blacklist/whitelist rules from the database and imports them into the agent's SQLite on the remote server.

### Scan
Triggers remote scan and retrieves results as JSON.

## Cron Setup

For automatic scanning, add to crontab:
```
*/5 * * * * php /path/to/bin/console antispam:agent:scan-all
```
