# Deployment

## Docker Compose (Coolify or plain Docker)

The repository ships a production-ready Docker setup:

- `Dockerfile` - PHP 8.2 + Apache image with the IMAP / pdo_mysql / intl /
  zip / opcache extensions required by the app. Document root is pointed at
  `public/` and composer dependencies are installed without dev packages.
- `docker-compose.yml` - two services, `app` and `db` (MariaDB 10.6), linked
  through a private network with healthchecks and named volumes for the
  database data, the application data (`var/data`) and the log directory.
- `docker/entrypoint.sh` - freezes the environment variables into
  `.env.local.php` at every container start (Apache does not pass the container
  environment to PHP), waits for MySQL, rebuilds the Symfony cache and
  upgrades the database schema with `antispam:db:upgrade` (Doctrine Migrations,
  see [Database schema at boot](#database-schema-at-boot)). It also hashes `ADMIN_PASSWORD` (bcrypt) so
  the operator never handles password hashes directly, and builds
  `MAILER_DSN` from the legacy `MAILER_HOST` / `MAILER_USER` /
  `MAILER_PASSWORD` variables when it is not set.
- `.env.example` - all supported variables with safe-to-commit defaults.

### Required environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `APP_SECRET` | Symfony secret for CSRF / session signing | `ChangeMeInProductionPlease` |
| `ADMIN_USER` | Login for the web UI | `admin` |
| `ADMIN_PASSWORD` | Password for the web UI (bcrypted on startup) | `admin` |
| `ADMIN_PASSWORD_HASH` | Pre-computed bcrypt hash (skip runtime hashing) | _(unset)_ |
| `ADMIN_TOTP_SECRET` | Optional 2FA (TOTP) of `ADMIN_USER`: base32 secret from `php bin/console antispam:2fa:secret`, added to an authenticator app. Empty = the env admin logs in with the password only, even when "Wymagaj 2FA dla administratorów" is on. Database users set 2FA up in the panel instead - see [users.md](users.md#two-factor-authentication-2fa) | _(empty)_ |
| `DATABASE_NAME` | MySQL database name | `antispam` |
| `DATABASE_USER` | MySQL user | `antispam` |
| `DATABASE_PASSWORD` | MySQL user password | `antispam` |
| `DATABASE_ROOT_PASSWORD` | MariaDB root password | `rootpassword` |
| `DATABASE_SERVER_VERSION` | Database server version for Doctrine (`8.0.36` for MySQL) | `10.6.0-MariaDB` |
| `MAILER_DSN` | Symfony Mailer DSN, e.g. `smtp://user:pass@smtp.example.com:587` | _(empty = mail disabled)_ |
| `MAILER_HOST` / `MAILER_USER` / `MAILER_PASSWORD` | Legacy (Swiftmailer) settings, used to build `MAILER_DSN` (`smtp://…:25`) when it is empty | _(empty)_ |
| `RUN_MIGRATIONS` | Run `antispam:db:upgrade` (Doctrine Migrations) at boot; `false` = you run it after each deploy | `true` |
| `RUN_MIGRATIONS_STRICT` | `true` = the container exits when the upgrade fails (default: ERROR banner in the log, Apache starts anyway) | `false` |
| `SSH_KEYS_DIR` | Directory with the SSH private keys of SSH+Maildir accounts | `var/data/ssh-keys` |
| `ALLOW_INSECURE_DEFAULTS` | `1` lets the container start with default/empty secrets (local testing only) | `0` |
| `SYMFONY_TRUSTED_PROXIES` | Comma-separated IPs / CIDRs whose `X-Forwarded-*` headers are trusted (Coolify's Traefik, a host nginx), so Symfony sees `https://` and the real client IP (HSTS, login throttling, absolute URLs) - see [Behind a reverse proxy](#behind-a-reverse-proxy-nginx) | private ranges (compose files) |

The container **refuses to start** while `APP_SECRET`, `ADMIN_PASSWORD` (or
`ADMIN_PASSWORD_HASH`) or `DATABASE_PASSWORD` is empty or left at the default
above. Set them in Coolify (or `.env`); `ALLOW_INSECURE_DEFAULTS=1` skips the
check for local testing only.

## Deploying on Coolify

1. **Create the resource.** In Coolify click *+ New* > *Docker Compose* and
   point it at this repository (branch `master` or a deployment branch of
   your choice). Coolify will auto-detect `docker-compose.yml`.

2. **Set environment variables.** Open the *Environment Variables* tab and
   define at minimum:

   ```env
   APP_SECRET=<openssl rand -hex 32>
   ADMIN_USER=<your login>
   ADMIN_PASSWORD=<strong password>   # always-available admin; more users: docs/users.md
   DATABASE_PASSWORD=<random>
   DATABASE_ROOT_PASSWORD=<random>
   ```

   Everything else can be left on its default. If you supply your own
   bcrypt hash via `ADMIN_PASSWORD_HASH`, `ADMIN_PASSWORD` is ignored.

3. **Bind a domain.** Open the *Domains* tab on the `app` service, add your
   FQDN (e.g. `antispam.example.com`) and point the port to `80`. Coolify's
   Traefik proxy will request a Let's Encrypt certificate automatically.

4. **Deploy.** Hit *Deploy*. First build takes a few minutes (composer
   install + PHP extension compile). After deployment:

   - `https://antispam.example.com/` -> public home page with the login form
     (section *Zaloguj się do panelu*)
   - Log in with the credentials you set in step 2; the dashboard is at `/panel`.

5. **Persistence.** Coolify creates three named volumes automatically:
   `db_data` (MariaDB), `app_data` (`var/data` - markers of already checked IMAP messages, scan locks
   and SSH keys) and `app_logs` (Symfony logs). They survive redeploys and
   container restarts.

### Production compose with scheduler (`docker-compose.prod.yml`)

`docker-compose.prod.yml` is the recommended file for Coolify. It adds a
`scheduler` service, so no host crontab is needed. In Coolify set
*Docker Compose Location* to `/docker-compose.prod.yml` and bind the domain to
the `app` service on port `80`.

| Service | Role |
| --- | --- |
| `app` | Apache + PHP, web UI. Runs `antispam:db:upgrade` (migrations) at boot; healthy once Apache is up |
| `db` | MariaDB 10.6 (volume `db-data`) |
| `scheduler` | Same image, runs `docker/scheduler.sh` instead of Apache. No migrations; starts after `app` is healthy |
| `clamav` | ClamAV daemon (`clamav/clamav-debian:1.4`, multi-arch) for attachment scanning; signatures in volume `clamav-db` |

`app` and `scheduler` share `app-data` (`var/data`) and `app-logs` (`var/log`).
The scheduler ticks once a minute and runs each command as `www-data`. A job
that is still running is skipped on the next tick (flock). Every job goes
through `antispam:cron:run`, so its runs and output are visible in the panel
on **Przegląd → Logi crona** (see [spam-handling.md](spam-handling.md)).

| Variable | Command | Default |
| --- | --- | --- |
| `SCAN_INTERVAL` | `antispam:agent:scan-all` (SSH agents, IMAP accounts, legacy mailbox) every N minutes (`0` = off) | `5` |
| `FEED_SYNC_INTERVAL` | `antispam:feed:sync` every N minutes (`0` = off) | `15` |
| `CERT_SYNC_INTERVAL` | `antispam:cert:sync` (CERT Polska domain list) every N hours at minute :17 (`0` = off) | `6` |
| `PHISHING_FORWARD_INTERVAL` | `antispam:phishing:forward` (automatic phishing forward to CERT Polska / SOC, see [phishing.md](phishing.md)) every N minutes (`0` = off) | `10` |
| `DIGEST_HOUR` | `antispam:digest:send` daily at HH:00, container time = UTC (`off` = off); every other full hour `antispam:digest:send --scheduled-only` for mailboxes with their own send hour | `7` |
| `PURGE_HOUR` | `antispam:purge` (score log retention, expired DNSBL cache) daily at HH:41, UTC (`off` = off) | `3` |
| `RESCAN_DUE` | `antispam:rescan:due` hourly at minute 7: queues the weekly full rescans of accounts that have them on (`off` = off) | `on` |
| `JOB_TIMEOUT` | any job running longer is killed (`timeout -k 30`), so a hung run cannot hold its flock and block every later tick | `3600` s |
| `SCAN_MAX_SECONDS` | time budget of one IMAP mailbox per `scan-all` run; the rest of a huge INBOX is scanned on the next run | `600` s |
| `JOBS_WORKER` | background job worker `antispam:jobs:work` (runs what the panel queues: Skanuj, Wdróż, Synchronizuj, new rule → existing mail, CERT sync...), started next to the ticks and restarted when it exits (`off` = none) | `on` |
| `JOBS_WORKER_TIME_LIMIT` | the worker exits after N s and is restarted fresh | `3600` |
| `JOBS_JOB_TIMEOUT` | one background job may run N s | `3900` |
| `JOBS_BATCH_SECONDS` | length of one batch of a big IMAP scan job | `120` |

The feed sync, the CERT list sync, the phishing forward and the digest do nothing while they are disabled in the panel
settings, so leaving them on is safe.

**Background jobs.** Heavy panel buttons only queue a job (table `antispam_job`); the worker in the
`scheduler` service runs it within ~2 s ([jobs.md](jobs.md)). Without the `scheduler` (plain
`docker-compose.yml`, or no Docker) nothing runs them - add `* * * * * php bin/console antispam:jobs:run --once`
to the crontab or run `antispam:jobs:work` under systemd / supervisord. A stuck queue shows up in
*Stan systemu* (check `jobs`), `/metrics` and `antispam:doctor`. The image includes `pcntl` for the
per-job time limit. The scheduler's output is in the
`scheduler` service logs in Coolify.

### ClamAV

Both compose files include a `clamav` service (clamd + freshclam, which
updates signatures on its own). To use it, in the panel open
**Ustawienia → Filtr spamu**:

1. *Skanowanie załączników (ClamAV)* → *Adres clamd*: `tcp://clamav:3310`;
2. turn on ClamAV scanning in the scoring section and save;
3. press the ClamAV connection test button - it should report that the daemon
   answers.

The first start downloads the signature database (a few minutes, the
healthcheck allows 5); until then the test fails. clamd needs about
1.5-2 GB of RAM. Port 3310 is only reachable inside the stack, so it serves
the server-side scans (IMAP accounts, legacy mailbox, mail client plugins).
SSH agents get the same DSN with their settings but cannot reach it from
another server - the connection fails and the attachment is treated as clean (no virus scan, no penalty).
For agents, run clamd on the mail server and use a separate install there.

### Updating

Push a new commit to the branch Coolify is tracking and press *Redeploy*.
The entrypoint runs `antispam:db:upgrade` on every boot, so the migrations of
the new release are applied before Apache starts. To apply them yourself
instead (maintenance window, DB backup first), set `RUN_MIGRATIONS=false` and run
`docker compose exec app php bin/console antispam:db:upgrade --dry-run`, then
without `--dry-run`, after each deploy.

### Database schema at boot

With `RUN_MIGRATIONS=true` (default) the `app` container runs
`doctrine:database:create --if-not-exists` and `antispam:db:upgrade`
([migrations.md](migrations.md)) before Apache starts; the `scheduler` never
touches the schema. `antispam:db:upgrade` picks the path by itself:

| Database | Boot does |
| --- | --- |
| empty (new install) | runs all migrations - the baseline creates the full schema |
| created by an older release (`doctrine:schema:update` at boot, before migrations) | one last `schema:update` to the current entities (every statement is logged, column drops tagged `[DROPS DATA]`, unknown tables are never dropped), records the baseline as executed |
| already migrated | runs the pending migrations; nothing to do = `No pending migrations.` |

Its lines start with `[db:upgrade]` in the `app` logs. On failure the
entrypoint prints an ERROR banner and still starts Apache (as the old
`schema:update || true` did): a crash loop would hide the panel and `/health`,
which report the problem (`antispam:doctor` / health check `schema`). Fix the
cause and restart the container, or run `antispam:db:upgrade` by hand. Set
`RUN_MIGRATIONS_STRICT=true` to make the container exit instead. Exit code `2`
(warning banner) means an entity change without a migration or a database
upgraded by a newer release - see [migrations.md](migrations.md).

**Upgrading from 2.0.0 or older** needs no manual step: the first boot of the
new image adopts the database (path 2 above). Take the usual database backup
before the redeploy ([Backup and restore](#backup-and-restore)); to see the plan
first run the new image once with `RUN_MIGRATIONS=false` and
`php bin/console antispam:db:upgrade --dry-run` in it.

To check which release a host runs: the panel footer (admins) shows
`wersja 2.0.0 (abc1234)` and links to *Co nowego* (`/changelog`);
`GET /api/plugin/status` returns `server_version`; in the container
`php bin/console --version` prints `Antispam Pancernapanda 2.0.0 (abc1234)`.
A commit of `nieznany` / no hash means the image was built without
`GIT_COMMIT` (see [Releasing](#releasing)).

### Rotating the admin password

Change `ADMIN_PASSWORD` in Coolify's env variables screen and redeploy (or
restart the `app` service). The entrypoint re-hashes the password and
regenerates `.env.local.php` on startup, so the new credentials are picked
up on the next request.

### Backup and restore

Three things make up an instance; back up all of them (e.g. nightly, keep a few days):

| What | Where | Contains |
| --- | --- | --- |
| Database | `db` service, volume `db-data` | everything: settings, rules, accounts, users, quarantine index, score log, phishing reports |
| Application data | volume `app-data` = `var/data` | SSH private keys (`ssh-keys/`), checked-message markers, scan locks |
| Environment | Coolify env screen / `.env` | `APP_SECRET` (encryption key of stored passwords and digest links), DB passwords, `ADMIN_*`, `MAILER_DSN` |

Without the same `APP_SECRET` a restored database cannot decrypt the stored IMAP
passwords - keep it with the backup (in a password manager, not next to the dump).

```bash
# 1. database dump (consistent, without locking InnoDB tables)
docker compose exec -T db sh -c 'exec mariadb-dump --single-transaction --routines -uroot -p"$MARIADB_ROOT_PASSWORD" "$MARIADB_DATABASE"' \
  | gzip > antispam-db-$(date +%F).sql.gz

# 2. var/data volume (SSH keys!) - via the app container
docker compose exec -T app tar -C /var/www/html/var -czf - data > antispam-data-$(date +%F).tar.gz

# 3. optional: configuration-only backup (portable between servers, see backup.md)
docker compose exec -T -u www-data app php bin/console antispam:export > antispam-config-$(date +%F).json
```

(MariaDB 10.6 also has `mysqldump`; with the `docker-compose.prod.yml` stack use
`docker compose -f docker-compose.prod.yml ...`.)

Restore on a new or the same server:

```bash
# start the stack with the SAME APP_SECRET, then stop the writers
docker compose up -d db app && docker compose stop scheduler
gunzip -c antispam-db-2026-10-28.sql.gz \
  | docker compose exec -T db sh -c 'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" "$MARIADB_DATABASE"'
docker compose exec -T app tar -C /var/www/html/var -xzf - < antispam-data-2026-10-28.tar.gz
docker compose exec app chown -R www-data:www-data /var/www/html/var/data
docker compose exec app chmod 700 /var/www/html/var/data/ssh-keys
docker compose restart app && docker compose start scheduler   # entrypoint runs antispam:db:upgrade
docker compose exec -u www-data app php bin/console antispam:doctor
```

Only the configuration (fresh database, another server, another customer): restore
`var/data/ssh-keys` as above, then `antispam:import file.json --dry-run` and
`antispam:import file.json` - see [backup.md](backup.md). The panel offers the same
under **Ustawienia → Kopia zapasowa**. Run `antispam:doctor` after every restore.

## Running with plain docker-compose

For local / VPS deployments without Coolify:

```bash
cp .env.example .env
# edit .env - at minimum set APP_SECRET, ADMIN_PASSWORD, DATABASE_PASSWORD
docker compose up -d --build
```

The app listens on port 80 inside the container. To expose it on the host,
change `expose:` to `ports: ["8080:80"]` in `docker-compose.yml`.

## Security checklist

Before exposing the instance publicly, make sure:

- [ ] `APP_SECRET` is a random 32+ char value, not the default. It also signs
      the quarantine digest links. While it is the default, the digest is
      disabled and `/q/` rejects every link. Changing it invalidates links
      already sent.
- [ ] `ADMIN_PASSWORD` is strong and not `admin`.
- [ ] Two-factor authentication: create a database administrator (*Ustawienia →
      Użytkownicy*), enable 2FA for it (*menu konta → Weryfikacja dwuetapowa*),
      turn on **Wymagaj 2FA dla administratorów**, and set `ADMIN_TOTP_SECRET`
      for the env admin (`php bin/console antispam:2fa:secret`) - without it the
      env admin keeps logging in with the password only. See
      [users.md](users.md#two-factor-authentication-2fa).
- [ ] `DATABASE_PASSWORD` / `DATABASE_ROOT_PASSWORD` are random.
- [ ] The domain is served over HTTPS (Coolify handles this automatically).
      In prod the session cookie is always `Secure` (`cookie_secure: true`
      under `when@prod`), so logging in over plain `http://` (other than
      `localhost`) does not work.
- [ ] The reverse proxy is trusted (`SYMFONY_TRUSTED_PROXIES`) and sends
      `X-Forwarded-Proto` / `X-Forwarded-For` - otherwise there is no HSTS
      header and the login throttling counts every visitor as the proxy's IP.
      Check: `curl -sI https://antispam.example.com/ | grep -i strict-transport`.
- [ ] Access to the `db` service is not exposed - only the `app` service
      should be reachable from the internet.
- [ ] Request body limit of the reverse proxy in front of antispam: nginx
      defaults to `client_max_body_size 1m`. Mail client plugins send at most
      700 KiB of a message by default (~0.95 MB request), which fits. To accept
      whole phishing reports with attachments (up to 10 MiB), raise it, e.g.
      `client_max_body_size 16m;` (Traefik in Coolify has no default limit),
      and then raise **Maks. wysyłana wiadomość** in *Ustawienia → Wtyczki
      pocztowe* to match (`plugin.max_upload_kb`, published to the plugins as
      `max_upload_bytes`). See [thunderbird.md](thunderbird.md#http-api-apiplugin).
- [ ] If you use the [quarantine digest](quarantine-digest.md), `/q/` must be
      reachable by mailbox owners. It is the only anonymous route besides
      the home page `/`, `/login` and `/api/feed`. Set `MAILER_DSN` and either use
      `docker-compose.prod.yml` (the scheduler sends it) or schedule
      `antispam:digest:send` in cron.
- [ ] Monitoring: point an uptime monitor at `/health` (public, only
      `ok|degraded|fail`, HTTP 503 on failure), set an alert recipient or
      webhook in *Przegląd → Stan systemu* and click **Wyślij testowy alert**.
      See [health.md](health.md).

IMAP passwords in the `account` table and the password of the legacy
single-account settings (*Konfiguracja → E-mail*) are encrypted with a key
derived from `APP_SECRET` (values saved before this change stay readable as
plain text until they are saved again - open the page, type the password once
and save). Changing `APP_SECRET` makes them unreadable: enter them again.
Stored passwords and API keys (VirusTotal, Safe Browsing, feed keys) are never
rendered back into the settings forms. The API keys themselves are kept in
plain text in the `config` table, so treat access to the database (and its
backups) as sensitive.

### Login throttling

The login form allows 5 failed attempts per login + client IP within 15 minutes
(and 25 per IP across all logins), then answers "Zbyt wiele nieudanych prób
logowania, spróbuj ponownie po upływie N minut" until the window passes (`login_throttling` in
`config/packages/security.yaml`, `symfony/rate-limiter`, state in the
`cache.rate_limiter` pool = `var/cache`). A successful login resets the
counter; restarting the container (cache rebuild) clears it as well. The
client IP is only correct with a trusted proxy (next section).

The 2FA code step (`/2fa`) and the 2FA forms of `/my/2fa` have their own limiter,
`two_factor_code` in `config/packages/framework.yaml`: 5 wrong codes per login
within 15 minutes (keyed by login only), same storage; a correct code resets it.

### Behind a reverse proxy (nginx)

Production runs the container behind a host nginx that terminates TLS. Symfony
trusts `X-Forwarded-*` only from the addresses in `SYMFONY_TRUSTED_PROXIES`;
without that it sees `http://` and the proxy's IP. The compose files default
to `127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`, which covers nginx
reaching the container through a published port or a Docker network (the
request then comes from the bridge gateway, e.g. `172.17.0.1`). Narrow it to
the real proxy address if the container is reachable from elsewhere, e.g.
`SYMFONY_TRUSTED_PROXIES=172.17.0.1`. nginx must send the headers:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name antispam.example.com;
    # ssl_certificate / ssl_certificate_key ...

    client_max_body_size 16m;            # phishing reports with attachments

    location / {
        proxy_pass http://127.0.0.1:8080;  # container port 80 published as 8080
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;   # overwrite, do not append client input
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-Port  $server_port;
    }
}

server {
    listen 80;
    server_name antispam.example.com;
    return 301 https://$host$request_uri;
}
```

Do not add `X-Frame-Options` / CSP / HSTS in nginx as well: the app sets them
per route (the Outlook add-in must stay frameable) and duplicate headers are
combined by browsers in surprising ways. `server_tokens off;` in nginx hides
its version.

### Security headers

Set by `AntispamBundle\EventListener\SecurityHeadersListener` on every
response (a header the controller already set wins):

| Route | Content-Security-Policy | X-Frame-Options |
| --- | --- | --- |
| panel, `/my`, home page `/`, `/login`, error pages | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` | `DENY` |
| `/q/*` (digest links; same-origin script files only, no inline JS) | `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` | `DENY` |
| `/plugin/outlook/*` (task pane framed by Outlook, loads office.js from appsforoffice.microsoft.com) | none | none |
| non-HTML responses (JSON API, downloads) | none | `DENY` |

All responses: `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`
(`/q/` pages: `no-referrer`), `Permissions-Policy: camera=(), microphone=(),
geolocation=(), payment=()`, and in prod over https
`Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`).

`'unsafe-inline'` is still allowed for scripts, so the inline code that is
left keeps working: the two `<script>` blocks of `main.html.twig`, the
Thunderbird / Outlook / Spambox templates noted by the UI batch and the
`onsubmit="return confirm(...)"` of the rule list templates (Whitelist,
DomainBlacklist, EmailBlacklist, EmailWhitelist). New code uses
`data-confirm="..."` (`Resources/public/js/data-confirm.js`, included by each
template that needs it) and external script files. Once the remaining inline
code is moved out, drop `'unsafe-inline'` from `script-src` in
`SecurityHeadersListener::POLICY_DEFAULT` (consider shipping it as
`Content-Security-Policy-Report-Only` for a while first).
The spam folder preview (`/spambox/index`) renders the message in a
`sandbox=""` iframe whose document carries its own
`default-src 'none'; img-src data:` policy, so tracking pixels and remote CSS
of spam are never fetched.

The image also sets `ServerTokens Prod`, `ServerSignature Off`,
`TraceEnable Off`, `nosniff` for static files
(`docker/apache-security.conf`) and `expose_php = Off` (`docker/php.ini`), so
neither `Server` nor `X-Powered-By` reveals versions.

## Releasing

The version lives in one place: `AntispamBundle\AppVersion::VERSION`
(`src/AntispamBundle/AppVersion.php`, [semver](https://semver.org)). It is
exposed as the container parameter `antispam.version` and the Twig global
`antispam_version` (`version`, `commit`, `full`). Other code (exports, health
checks) should read the parameter or the constant, never parse `CHANGELOG.md`.

1. **Pick the number.** MAJOR for changes an operator or user must act on or
   will notice (roles, rule semantics, agent protocol, removed settings,
   incompatible API fields); MINOR for new features and additive API fields;
   PATCH for fixes only.
2. **Bump** `AppVersion::VERSION`.
3. **Update `CHANGELOG.md`** ([Keep a Changelog](https://keepachangelog.com)):
   move the *Unreleased* entries into a new `## [x.y.z] - YYYY-MM-DD` section,
   move the `(current)` marker to it and leave an empty *Unreleased* on top.
   Group under *Added / Changed / Deprecated / Removed / Fixed / Security*.
4. **Mail client plugins** have their own versions; bump them only when the
   plugin code or manifest changed:
   - Thunderbird: `version` in `Resources/thunderbird/manifest.json` **and**
     `PluginApiController::PLUGIN_VERSION` (same value - it is the `?v=` cache
     buster of the `.xpi` link, `version` in `/api/plugin/status` and in
     `/plugin/thunderbird/updates.json`, which makes installed instance builds
     update themselves). For a store release tag `thunderbird-v<version>`
     (workflow `thunderbird-plugin.yml`) and, after ATN review, upload the new
     package in every panel - an uploaded package of an older version stops
     being served. See [plugin-distribution.md](plugin-distribution.md).
   - Outlook: `<Version>` in `Resources/outlook/manifest.xml` (four parts,
     `1.1.0.0`; Outlook caches add-ins by it).
   - New `/api/plugin` response fields are additive; a plugin must keep
     working against an older server (missing field = feature off).
5. **SSH+Maildir agent:** bump `AGENT_VERSION` in
   `Resources/agent/antispam-agent.php` whenever the agent script changes.
   The panel compares every agent answer with the bundled version
   (`SshService::bundledAgentVersion()`) and asks to redeploy an older agent
   (*Konta → Wdróż*).
6. **Database migrations:** every entity change since the last release must
   have a migration in `migrations/` (`doctrine:migrations:diff` against a dev
   database at the previous release, review, commit - see
   [migrations.md](migrations.md#adding-a-migration-developers)). Check on a dev
   database with all migrations applied: `bin/console antispam:db:upgrade` exits
   `0` (not `2`) and `bin/console doctrine:schema:validate` is in sync. Never
   edit a released migration.
7. **Verify:** `vendor/bin/phpunit`, `bin/console lint:container`,
   `bin/console lint:twig src/AntispamBundle/Resources/views templates`,
   `docker build .`.
8. **Commit and tag** on `master`: `git commit -m "Release x.y.z"`,
   `git tag -a vx.y.z -m "x.y.z"`, `git push --follow-tags`. Then redeploy in
   Coolify and confirm `server_version` / the footer on the host.

### Build commit (`GIT_COMMIT` / Coolify `SOURCE_COMMIT`)

`.git` is not in the Docker build context (`.dockerignore`), so the commit
comes in as the build arg `GIT_COMMIT` (default `unknown`) and is written to
`/var/www/html/REVISION`; `AppVersion` accepts only a hex hash from it and
shows the first 7 characters. Both compose files pass
`GIT_COMMIT: ${GIT_COMMIT:-${SOURCE_COMMIT:-unknown}}`.

- **Coolify** provides the deployed commit as the predefined variable
  `SOURCE_COMMIT`, but excludes it from Docker builds by default to keep the
  build cache. Set *Advanced → Build → Source commit availability* to
  *Available during build* on the resource (Coolify docs, *Environment
  variables → Predefined variables*). Otherwise the panel shows commit
  `nieznany` - the version number is still correct.
- **Plain Docker / compose:**
  `docker build --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) .` or
  `GIT_COMMIT=$(git rev-parse --short HEAD) docker compose build`.

The `ARG` is declared after `COPY . .`, so a new commit only rebuilds the last
layers.
