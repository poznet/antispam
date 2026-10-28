# Configuration backup / restore and `antispam:doctor`

Two layers of backup:

| What | How | Use it for |
| --- | --- | --- |
| **Configuration backup** (this page) | `antispam:export` / `antispam:import`, panel **Ustawienia → Kopia zapasowa** (`/backup`) | predictable installs, moving a customer to another server, restoring settings and rules |
| **Full server backup** | `mysqldump` of the `db` container + the `app-data` volume (`var/data`: SSH keys, scan markers) | disaster recovery - see [deployment.md](deployment.md#backup-and-restore) |

The configuration backup contains **settings, list rules, DNSBL providers, accounts and users**.
It never contains runtime data: quarantine, score log, cron log, phishing reports (or their
metadata), plugin reports, shared feed signals, CERT list, DNSBL cache, scan cursors and
last-scan results.

## File format

One JSON document (UTF-8, pretty printed), optionally inside a ZIP as
`antispam-backup.json` (+ `README.txt`).

```json
{
  "format": "antispam-backup",
  "schema_version": 1,
  "app_version": "1.4.0",
  "exported_at": "2026-10-28T12:00:00+00:00",
  "include_secrets": false,
  "secrets": null,
  "settings": {
    "config": { "scoring.spam_threshold": 7, "plugin.public_url": "https://antispam.example.pl" },
    "lists":  { "impersonation.protected_domains": "firma.pl\nfirma.com" }
  },
  "rules": {
    "blacklist":       [{ "owner": "*", "value": "spam.example", "pattern_type": "exact", "score": 12, "hits": 5 }],
    "whitelist":       [{ "owner": "jan@firma.pl", "value": "partner.pl", "pattern_type": "exact", "hits": 0 }],
    "email_blacklist": [{ "owner": "*", "value": "^.*@spam\\.ru$", "pattern_type": "regex", "score": 20, "hits": 0 }],
    "email_whitelist": [{ "owner": "*", "value": "szef@firma.pl", "pattern_type": "exact", "hits": 0 }]
  },
  "dnsbl": [{ "name": "Spamhaus ZEN", "zone": "zen.spamhaus.org", "score": 6, "enabled": true, "cache_ttl": 3600, "hits": 42 }],
  "accounts": [{
    "email": "jan@firma.pl", "name": "Jan", "connection_type": "imap", "delete_spam": true,
    "imap_host": "imap.firma.pl", "imap_port": 993, "imap_login": "jan@firma.pl", "imap_flags": "/imap/ssl",
    "ssh_host": null, "ssh_port": 22, "ssh_user": null, "maildir_path": "~/Maildir", "agent_path": "~/antispam-agent",
    "ssh_host_key": null, "agent_deployed": false
  }],
  "users": [{ "username": "jan", "role": "ROLE_USER", "accounts": ["jan@firma.pl"] }]
}
```

| Field | Notes |
| --- | --- |
| `schema_version` | `BackupFormat::SCHEMA_VERSION` (now `1`). An import refuses a newer version ("update the application first"); older versions stay readable. Bump it on any incompatible change of the format. |
| `app_version` | Read defensively: container parameter `app.version` / `antispam.version`, else a `VERSION` file in the project root, else `null` (`Services\Backup\AppVersion`). Informational only. |
| `settings.config` | Every row of the `config` table except secrets and runtime state (`cert.last_*`, `feed.last_*`, `digest.last_sent.*`, `imap.legacy_cursor` - `BackupSecrets::STATE_PREFIXES`). Scalar values only. |
| `settings.lists` | `antispam_list_setting` (protected domains, VIPs, URI DBL zones, blocked extensions). |
| `rules.*` | All four lists with owner (`*` = all mailboxes, see [scoring.md](scoring.md#rule-ownership)), pattern type, score (blacklists) and hit counter (`hits`, only used when a rule is created). |
| `accounts` | Connection settings. `ssh_host_key` is the pinned public fingerprint (kept so the TOFU pin survives a move), not a secret. |
| `users` | Username, role, assigned mailboxes by e-mail. The legacy `ADMIN_USER` administrator lives in the environment and is never exported. |

### Secrets

Without `--include-secrets` (and in the panel's default download) these stay on the server:

- legacy mailbox password (`config.password`), VirusTotal / Safe Browsing API keys
  (`scoring.vt_api_key`, `url.gsb_api_key`), shared feed keys (`feed.server_key`,
  `feed.remote_key`) - `BackupSecrets::CONFIG_KEYS`;
- account IMAP passwords, plugin password hashes and SSH key paths;
- user password hashes.

With `--include-secrets` the file gets `"include_secrets": true`, a
`secrets` block (`cipher`, `key_check`) and the values above. **Every secret is
encrypted with the instance key** (`CryptoService`, libsodium secretbox, key derived
from `APP_SECRET`) - also the API keys and hashes that the database keeps in plain
text. Anyone with the file *and* the `APP_SECRET` can read them: store such a backup
like a password. The SSH key path is a pointer, not key material; the key file itself
travels with `var/data/ssh-keys` (volume backup).

On import the `key_check` value is decrypted first. If the target runs with a
different `APP_SECRET`, **all secrets are skipped with a warning** and everything
else is imported; enter the passwords / keys again in the panel, or start the target
with the source's `APP_SECRET` (then also the digest links keep working).

## antispam:export

```bash
php bin/console antispam:export --output=backup.json            # without secrets
php bin/console antispam:export --output=backup.zip             # ZIP (needs ext-zip)
php bin/console antispam:export --output=full.json --include-secrets
php bin/console antispam:export > backup.json                   # JSON on stdout, messages on stderr
```

The file is written with mode `0600`; an existing file is only overwritten with
`--force`. Docker: `docker compose exec -u www-data app php bin/console antispam:export --output=var/data/backup.json`
(then `docker compose cp app:/var/www/html/var/data/backup.json .`).

## antispam:import

```bash
php bin/console antispam:import backup.json --dry-run                 # preview, writes nothing
php bin/console antispam:import backup.json                           # merge
php bin/console antispam:import backup.zip --only=rules,dnsbl
php bin/console antispam:import backup.json --mode=replace --dry-run
php bin/console antispam:import backup.json --mode=replace --confirm-replace
```

- **Validation first**: format marker, `schema_version`, the shape of every section.
  A broken or foreign file is rejected (exit 1) before anything is touched. Single
  invalid entries (bad regex or one too expensive to run, unknown pattern type, an
  account host with shell characters, a `ROLE_SUPER_ADMIN`, a non-http(s)
  `plugin.public_url` / `digest.base_url` / `feed.remote_url`) are skipped with a
  warning - the same rules as the panel forms (`AccountController::validateAccountData`,
  `PatternMatcher::validate`).
- **Natural keys**, never database ids: setting name, rule list + owner + pattern type +
  value (case-insensitive except regex), DNSBL zone, account e-mail, username.
- **merge** (default): create what is missing, update what differs, keep everything else.
- **replace**: merge, then delete the records of the selected sections that are not in
  the file. Needs `--confirm-replace` (panel: a checkbox). Matching records are updated
  in place, so surviving accounts keep their ids - and with them their quarantine keys
  (`imap-<id>` / `ssh-<id>`) and digest markers. Runtime state and secrets are never
  deleted. The admin running a panel import is never deleted.
- **One transaction**: an error rolls everything back ("Import failed, nothing was changed").
- **Secrets are never overwritten with an empty value**: a file without secrets (or with
  an empty one) keeps the current password / key.
- New users without a password hash get an unusable random one (warning: set a password
  under *Ustawienia → Użytkownicy*); IMAP accounts without a password get a warning too.
  The env administrator's login (`ADMIN_USER`) is reserved and skipped.
- A user's mailboxes are matched by e-mail against existing accounts and those created by
  the same import; unknown ones are reported and not assigned.
- The summary lists, per section, created / updated / unchanged / deleted / skipped plus
  the warnings. After an import push the rules to SSH agents: `antispam:agent:sync <accountId>`.

Sections for `--only`: `settings`, `rules`, `dnsbl`, `accounts`, `users`.

## Panel: Ustawienia → Kopia zapasowa

`/backup` (`BackupController`, `#[IsGranted('ROLE_ADMIN')]` on top of the `^/` access rule).

| Route | Method | What |
| --- | --- | --- |
| `/backup/` | GET | the page |
| `/backup/export` | POST + CSRF `backup_export` | download (JSON or ZIP). Without secrets by default; with secrets only after ticking the confirmation **and re-entering the logged-in admin's password** (checked with the password hasher; works for the env admin and database admins). `Cache-Control: no-store`. |
| `/backup/import` | POST + CSRF `backup_import`, multipart | upload (max 10 MB) + mode + sections → dry-run preview with the counts and warnings. The validated document waits in `var/backup-import/<random>.json` (0600), bound to the session, for at most one hour. |
| `/backup/import/apply` | POST + CSRF `backup_apply` | applies the previewed file (same mode / sections; replace needs the checkbox), then deletes it. A pending id from another session or an expired one is refused. |

## antispam:doctor

Configuration sanity check for a fresh install, after an upgrade or after moving a
customer. Not runtime monitoring (that is the health checks' job) - the only network
access is a ClamAV `PING` when ClamAV is enabled.

```bash
php bin/console antispam:doctor              # exit 1 when any check FAILs
php bin/console antispam:doctor --strict     # warnings make it exit 1 too (CI / deploy gate)
php bin/console antispam:doctor --format=json
docker compose exec -u www-data app php bin/console antispam:doctor
```

| Check | FAIL | WARN |
| --- | --- | --- |
| `version` | - | - (prints app version, PHP, environment) |
| `app_secret` | empty, the default `ChangeMeInProductionPlease`, < 16 chars | very few distinct characters |
| `encryption` | ext-sodium missing, key does not round-trip | |
| `php_extensions` | missing imap, mbstring, intl, curl, sodium, pdo_mysql | missing zip (ZIP backups) |
| `var_writable` | var/, var/cache, var/log, var/data not writable | SSH keys dir readable by others |
| `disk_space` | < 100 MB free on var/data | < 1 GB |
| `https` (prod only) | session cookie not always `Secure` | `SYMFONY_TRUSTED_PROXIES` empty (no https detection behind the proxy) |
| `database` | not reachable - every check below is then skipped | |
| `schema` | `doctrine:schema:update` has pending SQL | |
| `admin_login` | no `ADMIN_PASSWORD_HASH` and no ROLE_ADMIN user | |
| `mailer` | digest (or e-mail alerts) enabled but `MAILER_DSN` empty / `null://` | |
| `public_url` | | `plugin.public_url` not https / local host / empty while plugins are on; `digest.base_url` not https |
| `cron` | | nothing in the cron log, or the last job is older than 60 min |
| `accounts_scanned` | | accounts that never had a successful scan |
| `ssh_agents` | | deployed agents whose last reported `agent_version` is older than the bundled one |
| `stored_passwords` | encrypted IMAP passwords that do not decrypt (APP_SECRET changed) | legacy plaintext IMAP passwords (legacy mailbox or accounts) |
| `orphan_rules` | | list rules owned by a mailbox that no longer exists (they never match) |
| `feed` | hub URL without hub key | enabled with nothing configured, hub not https, short local key |
| `clamav` | enabled but clamd does not answer | |

E-mail alerting flags are read defensively (`alerts.enabled`, `alert.enabled`,
`health.alerts_enabled`) so the check also covers the alerting feature once present.

## Moving a customer to another server

1. Old server: `antispam:export --output=customer.json --include-secrets` (or the panel download with secrets).
2. Copy the SSH keys: `var/data/ssh-keys/*` (same file names - the accounts keep their key paths).
3. New server: same `APP_SECRET` as the old one if the secrets should come along.
4. `antispam:import customer.json --dry-run`, read the summary, then without `--dry-run`.
5. `antispam:doctor`, then `antispam:agent:sync <id>` for each SSH account and a test scan.
