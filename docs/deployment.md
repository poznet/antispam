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
| `CERT_SYNC_INTERVAL` | `antispam:cert:sync` (CERT Polska domain list) every N hours at minute :17 (`0` = off) | `6` |
| `DIGEST_HOUR` | `antispam:digest:send` daily at HH:00, container time = UTC (`off` = off) | `7` |
| `PURGE_HOUR` | `antispam:purge` (score log retention, expired DNSBL cache) daily at HH:41, UTC (`off` = off) | `3` |
| `JOB_TIMEOUT` | any job running longer is killed (`timeout -k 30`), so a hung run cannot hold its flock and block every later tick | `3600` s |

The feed sync, the CERT list sync and the digest do nothing while they are disabled in the panel
settings, so leaving them on is safe. The scheduler's output is in the
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
