# Account Management

## Overview

Each email account can be configured with one of two connection modes: IMAP or SSH+Maildir.

## IMAP Mode

Traditional mode using IMAP protocol to connect to mail server.

**Configuration fields:**
- **Email** - email address
- **IMAP Host** - mail server hostname
- **IMAP Port** - default 993
- **Login** - IMAP username
- **Password** - IMAP password, stored encrypted (libsodium, key derived from `APP_SECRET`). Leave it empty when editing to keep the current one. After changing `APP_SECRET` the passwords have to be entered again.
- **IMAP Flags** - connection flags (default: `/imap/ssl`; the old unencrypted setup is port 143 with `/novalidate-cert/notls`)

## SSH+Maildir Mode

Direct access to Maildir on hosting server via SSH.

**Configuration fields:**
- **Email** - email address
- **SSH Host** - hosting server hostname
- **SSH Port** - default 22
- **SSH User** - SSH username
- **SSH Key Path** - private key file in the keys directory on the Symfony server: a file name (e.g. `id_ed25519`) or an absolute path inside that directory
- **Maildir Path** - path to Maildir on hosting (default: `~/Maildir`)
- **Agent Path** - where to deploy agent (default: `~/antispam-agent`)

## SSH Key Setup

Keys are only read from the keys directory: `SSH_KEYS_DIR`, by default
`var/data/ssh-keys` (on the `app-data` / `app_data` volume in Docker). A key path
that resolves outside it (including via `..` or symlinks) is rejected, so the
field cannot be used to read other files of the server.

1. Generate SSH key pair: `ssh-keygen -t ed25519 -f var/data/ssh-keys/id_ed25519 -N ""`
   (in Docker: `docker compose exec -u www-data app ssh-keygen -t ed25519 -f var/data/ssh-keys/id_ed25519 -N ""`)
2. Add public key (`id_ed25519.pub`) to hosting's `~/.ssh/authorized_keys`
3. Set `id_ed25519` as the key path in account configuration

The account actions (Test, Scan, Deploy, Sync, Health, Delete) are POST
requests with a per-account CSRF token. Paths sent to the remote shell are
quoted; a leading `~/` still expands to the SSH user's home.

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
