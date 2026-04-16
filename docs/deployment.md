# Deployment

## Docker Compose (Coolify or plain Docker)

The repository ships a production-ready Docker setup:

- `Dockerfile` - PHP 7.4 + Apache image with the IMAP / iconv / pdo_mysql /
  intl / zip / opcache extensions required by the app. Document root is
  pointed at `web/` and composer dependencies are installed without dev
  packages.
- `docker-compose.yml` - two services, `app` and `db` (MariaDB 10.6), linked
  through a private network with healthchecks and named volumes for the
  database data, the Symfony cache and the log directory.
- `docker/entrypoint.sh` - renders `app/config/parameters.yml` from environment
  variables at every container start, waits for MySQL, warms Symfony cache,
  installs bundle assets and runs `doctrine:schema:update --force`. It also
  hashes `ADMIN_PASSWORD` (bcrypt) so the operator never handles password
  hashes directly.
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
| `MAILER_TRANSPORT` | Swiftmailer transport | `smtp` |
| `MAILER_HOST` | Swiftmailer host | `127.0.0.1` |
| `MAILER_USER` | Swiftmailer user | _(empty)_ |
| `MAILER_PASSWORD` | Swiftmailer password | _(empty)_ |
| `RUN_MIGRATIONS` | Run `doctrine:schema:update --force` at boot | `true` |

The defaults marked above are **insecure** and only exist to let the stack
boot for local testing. Override them in production.

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

   - `https://antispam.example.com/` -> redirects to `/login`
   - Log in with the credentials you set in step 2.

5. **Persistence.** Coolify creates three named volumes automatically:
   `db_data` (MariaDB), `app_cache` (Symfony prod cache) and `app_logs`
   (Symfony logs). They survive redeploys and container restarts.

### Updating

Push a new commit to the branch Coolify is tracking and press *Redeploy*.
The entrypoint runs `doctrine:schema:update --force` on every boot, so entity
changes are picked up without a manual migration step. If you do not want
that behaviour (for example because you manage schema via
`doctrine-migrations`), set `RUN_MIGRATIONS=false`.

### Rotating the admin password

Change `ADMIN_PASSWORD` in Coolify's env variables screen and redeploy (or
restart the `app` service). The entrypoint re-hashes the password and
regenerates `parameters.yml` on startup, so the new credentials are picked
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

- [ ] `APP_SECRET` is a random 32+ char value, not the default.
- [ ] `ADMIN_PASSWORD` is strong and not `admin`.
- [ ] `DATABASE_PASSWORD` / `DATABASE_ROOT_PASSWORD` are random.
- [ ] The domain is served over HTTPS (Coolify handles this automatically).
- [ ] Access to the `db` service is not exposed - only the `app` service
      should be reachable from the internet.

Note that IMAP passwords stored in the `account` table are currently kept in
plain text. Treat access to the database (and its backups) as sensitive.
