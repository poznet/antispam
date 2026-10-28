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
- **IMAP Flags** - c-client connection flags (default: `/imap/ssl`; the old unencrypted setup is port 143 with `/novalidate-cert/notls`)

### SSL/TLS options in the form

The account add/edit form and the legacy global config (`/config/email/`) build the flags from clickable
options (`AntispamBundle\Services\ImapFlags`, shared template `Account/_imap_security.html.twig`):

| Encryption | Flag | Default port |
|---|---|---|
| SSL/TLS (implicit, recommended) | `/ssl` | 993 |
| STARTTLS (required) | `/tls` | 143 |
| STARTTLS if available (opportunistic) | none | 143 |
| No encryption | `/notls` | 143 |

- **Certificate**: verify (default) or accept any certificate (`/novalidate-cert`) for self-signed
  certificates or a shared-hosting certificate issued for another name (e.g. `s1.hosting.pl` instead of `mail.domena.pl`).
- **Advanced**: `/secure` (no clear-text password auth), `/norsh`, `/debug`, or **custom flags** typed by
  hand (e.g. `/imap/ssl/readonly`). Stored flags the form cannot express open in custom mode, so nothing is lost.
- Switching encryption swaps the port between 993 and 143 if it still holds a default value; the full
  mailbox string (`{host:port/flags}`) is previewed live.

**Check connection and certificate** (`POST /account/imap-check`, CSRF `imap_check`, works before saving):
DNS, TCP, TLS handshake (implicit or STARTTLS), TLS version and cipher, the server certificate (CN, SANs,
issuer, validity, days left, hostname match, trusted chain, self-signed, SHA-256 fingerprint), server
capabilities (`STARTTLS`, `LOGINDISABLED`...) and, with a login given, a real c-client login with the chosen
flags (on edit an empty password uses the stored one). **Detect settings** tries 993 + SSL/TLS and
143 + STARTTLS and applies the working combination, keeping certificate verification on when the
certificate is trusted.

## SSH+Maildir Mode

Direct access to Maildir on hosting server via SSH.

**Configuration fields:**
- **Email** - email address
- **SSH Host** - hosting server hostname
- **SSH Port** - default 22
- **SSH User** - SSH username
- **SSH Key Path** - private key file in the keys directory on the Symfony server: a file name (e.g. `id_ed25519`) or an absolute path inside that directory
- **Maildir Path** - path to Maildir on hosting (default: `~/Maildir`)
- **Agent Path** - where to deploy agent (default: `~/antispam-agent`; `~/` is the SSH user's home both for SFTP uploads and for commands)
- **SSH host key** (read-only) - SHA256 fingerprint pinned on the first successful connection, see below

## SSH host key (trust on first use)

The first successful login stores the server's host key fingerprint
(`SHA256:...`, same format as `ssh-keygen -lf`) in `antispam_account.ssh_host_key`.
Every later connection (test, deploy, sync, scan, health, quarantine, digest)
compares the key **before** authenticating; a different key aborts with
"Klucz hosta SSH serwera ... zmienił się" and both fingerprints. If the change
is expected (server reinstalled, new key), compare the new fingerprint with
the hosting provider / `ssh-keyscan HOST | ssh-keygen -lf -` and use
**Resetuj klucz hosta SSH** on the account edit page (POST, CSRF-protected);
the next connection pins the key the server presents. Changing the SSH host or
port on the form also clears the pinned key. Accounts that existed before this
feature pin their key on the next connection.

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
Verifies SSH connectivity, shows the pinned host key and checks the remote
environment (PHP, SQLite3, mbstring, curl, Maildir).

### Deploy Agent
Uploads `antispam-agent.php` over SFTP (`~/` resolved against the SFTP home,
directory created `0700`, file `0600`, size verified), runs the agent's `test`
against the account's Maildir and only then marks the agent deployed. A failed
upload or self-test (e.g. missing mbstring) is shown as a failure. After a
successful deploy the rules and settings are synced right away.

### Sync Rules
Exports the account's whitelist / blacklist rules plus the global ones (owner **Wszystkie skrzynki**, `email = '*'`, see [scoring.md](scoring.md#rule-ownership)), DNSBL providers and the
scanning settings (thresholds, switches, impersonation, links, attachments,
CERT) and imports them into the agent's per-account SQLite database. The JSON
is uploaded as a temporary `0600` file and fed to `import-rules` on stdin
(works with older agents too); the import is all-or-nothing.

Panel rules are per mailbox: pick the account's e-mail (or **Wszystkie skrzynki**) in the mailbox selector of the white/blacklist forms - before this was added every panel rule belonged to the legacy mailbox and never reached any account.

### Scan
Triggers a remote scan with the panel's current thresholds and switches passed
as flags, and retrieves results as JSON. A timeout, an old agent, a locked
(already running) scan or a non-JSON answer is reported as a failed scan and
does not overwrite the account's last scan result.

### Timeouts and error messages
Each agent command has its own read timeout (`SshService::TIMEOUTS`: scan
3600 s, apply-blacklist 1800 s, import-rules 300 s, quarantine-list 180 s,
others 60 s; connect 15 s, keep-alive every 30 s). Stderr is kept apart from
the JSON on stdout. Typical messages: "Agent nie odpowiedział w ciągu N s",
"Agent na serwerze nie obsługuje polecenia ... - wdróż go ponownie",
"Nie znaleziono agenta na serwerze - wdróż go", "Brak PHP CLI". Answers from
an agent older than the bundled one carry `agent_warning` ("wdróż go
ponownie"), shown on the Sync / Scan / Health pages and in the console
commands. See [agent.md](agent.md) for the agent side.

## Cron Setup

For automatic scanning (all SSH and IMAP accounts), add to crontab:
```
*/5 * * * * php /path/to/bin/console antispam:cron:run antispam:agent:scan-all
```
`antispam:cron:run` records each run on **Przegląd → Logi crona**; see
[spam-handling.md](spam-handling.md). The Docker scheduler does this already.

Spam is moved to the account's `SPAM` folder unless *Usuwaj spam* is checked
(IMAP accounts). New blacklist rules are also applied to mail already in INBOX
(last 30 days).
