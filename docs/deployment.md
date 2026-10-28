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
  environment to PHP), waits for MySQL, rebuilds the Symfony cache and runs
  `doctrine:schema:update --force`. It also hashes `ADMIN_PASSWORD` (bcrypt) so
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
| `DATABASE_NAME` | MySQL database name | `antispam` |
| `DATABASE_USER` | MySQL user | `antispam` |
| `DATABASE_PASSWORD` | MySQL user password | `antispam` |
| `DATABASE_ROOT_PASSWORD` | MariaDB root password | `rootpassword` |
| `DATABASE_SERVER_VERSION` | Database server version for Doctrine (`8.0.36` for MySQL) | `10.6.0-MariaDB` |
| `MAILER_DSN` | Symfony Mailer DSN, e.g. `smtp://user:pass@smtp.example.com:587` | _(empty = mail disabled)_ |
| `MAILER_HOST` / `MAILER_USER` / `MAILER_PASSWORD` | Legacy (Swiftmailer) settings, used to build `MAILER_DSN` (`smtp://…:25`) when it is empty | _(empty)_ |
| `RUN_MIGRATIONS` | Run `doctrine:schema:update --force` at boot | `true` |
| `SSH_KEYS_DIR` | Directory with the SSH private keys of SSH+Maildir accounts | `var/data/ssh-keys` |
| `ALLOW_INSECURE_DEFAULTS` | `1` lets the container start with default/empty secrets (local testing only) | `0` |
| `SYMFONY_TRUSTED_PROXIES` | Comma-separated IPs / CIDRs whose `X-Forwarded-*` headers are trusted (Coolify's Traefik), so Symfony sees `https://` | private ranges |

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
   ADMIN_PASSWORD=<strong password>
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
   `db_data` (MariaDB), `app_data` (`var/data` - markers of already checked
   IMAP messages) and `app_logs` (Symfony logs). They survive redeploys and
   container restarts.

### Production compose with scheduler (`docker-compose.prod.yml`)

`docker-compose.prod.yml` is the recommended file for Coolify. It adds a
`scheduler` service, so no host crontab is needed. In Coolify set
*Docker Compose Location* to `/docker-compose.prod.yml` and bind the domain to
the `app` service on port `80`.

| Service | Role |
| --- | --- |
| `app` | Apache + PHP, web UI. Runs `doctrine:schema:update` at boot; healthy once Apache is up |
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
| `DIGEST_HOUR` | `antispam:digest:send` daily at HH:00, container time = UTC (`off` = off) | `7` |

The feed sync and the digest do nothing while they are disabled in the panel
settings, so leaving them on is safe. The scheduler's output is in the
`scheduler` service logs in Coolify.

### ClamAV

Both compose files include a `clamav` service (clamd + freshclam, which
updates signatures on its own). To use it, in the panel open
**Konfiguracja → Spam**:

1. *Skanowanie załączników (ClamAV)* → *Adres clamd*: `tcp://clamav:3310`;
2. turn on ClamAV scanning in the scoring section and save;
3. press the ClamAV connection test button - it should report that the daemon
   answers.

The first start downloads the signature database (a few minutes, the
healthcheck allows 5); until then the test fails. clamd needs about
1.5-2 GB of RAM. Port 3310 is only reachable inside the stack, so it serves
the server-side scans (IMAP accounts, legacy mailbox, mail client plugins).
SSH agents get the same DSN with their settings but cannot reach it from
another server - they report the error and treat the attachment as clean.
For agents, run clamd on the mail server and use a separate install there.

### Updating

Push a new commit to the branch Coolify is tracking and press *Redeploy*.
The entrypoint runs `doctrine:schema:update --force` on every boot, so entity
changes are picked up without a manual migration step. If you do not want
that behaviour (for example because you manage schema via
`doctrine-migrations`), set `RUN_MIGRATIONS=false`.

### Rotating the admin password

Change `ADMIN_PASSWORD` in Coolify's env variables screen and redeploy (or
restart the `app` service). The entrypoint re-hashes the password and
regenerates `.env.local.php` on startup, so the new credentials are picked
up on the next request.

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
- [ ] `DATABASE_PASSWORD` / `DATABASE_ROOT_PASSWORD` are random.
- [ ] The domain is served over HTTPS (Coolify handles this automatically).
- [ ] Access to the `db` service is not exposed - only the `app` service
      should be reachable from the internet.
- [ ] If you use the [quarantine digest](quarantine-digest.md), `/q/` must be
      reachable by mailbox owners. It is the only anonymous route besides
      the home page `/`, `/login` and `/api/feed`. Set `MAILER_DSN` and either use
      `docker-compose.prod.yml` (the scheduler sends it) or schedule
      `antispam:digest:send` in cron.

IMAP passwords in the `account` table are encrypted with a key derived from
`APP_SECRET` (rows saved before this change stay readable as plain text until
they are saved again). Changing `APP_SECRET` makes them unreadable: enter them
again. The legacy single-account settings (*Ustawienia → Email*) are still
stored in plain text. Treat access to the database (and its backups) as
sensitive.
