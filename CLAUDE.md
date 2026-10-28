# Antispam Pancernapanda

Symfony 7.4 LTS application for email spam filtering via IMAP or SSH+Maildir agent. Part of the Pancernapanda security toolkit.

## Project structure
- `src/AntispamBundle/` - main bundle (entities, controllers, services, commands, event listeners)
- `src/Kernel.php` - MicroKernel; `config/` - bundles, packages (`*.yaml`), routes, `services.yaml` (autowiring + listener priorities)
- `templates/bundles/TwigBundle/Exception/error.html.twig` - branded error page for every HTTP error (403/404/500...), standalone (no panel layout, renders before the firewall too)
- `public/` - web root (`index.php` front controller); `var/` - cache, logs, `var/data` (checked-message markers)
- `.env` - default env vars (override in `.env.local`; Docker freezes them into `.env.local.php`)
- `src/AntispamBundle/Resources/agent/` - standalone Maildir agent PHP script
- `src/AntispamBundle/Resources/thunderbird/` - Thunderbird plugin (MailExtension), served as .xpi by `/plugin/download`
- `src/AntispamBundle/Resources/outlook/` - Outlook add-in (manifest template + task pane), hosted under `/plugin/outlook/*`; `src/AntispamBundle/Resources/applemail/` - Apple Mail (MailKit) extension source, zipped by `/plugin/apple-mail/source.zip` (not buildable here, needs Xcode + Apple Developer signing)
- Home page `/` (`HomeController`, `Resources/views/Home/index.html.twig`, assets in `Resources/public/landing/`) - public product page for antispam.pancernapanda.pl with the admin login form embedded (`#logowanie`); the admin dashboard is at `/panel`

## Key concepts
- Two connection modes per account: IMAP (remote protocol) or SSH+Maildir (direct filesystem)
- Event-driven message processing pipeline (listeners with priorities)
- Standalone agent script for deployment on hosting servers

## Documentation
See `docs/` directory for detailed documentation:
- `docs/architecture.md` - system architecture and event pipeline
- `docs/agent.md` - Maildir agent: installation, commands, SQLite schema
- `docs/accounts.md` - account management: IMAP/SSH config, SSH keys, deploy
- `docs/commands.md` - CLI commands reference
- `docs/api.md` - web controller endpoints
- `docs/deployment.md` - Docker / Coolify deployment guide; "Releasing": version in `AntispamBundle\AppVersion::VERSION` (+ `CHANGELOG.md`, plugin/agent bump rules, build arg `GIT_COMMIT` -> `REVISION`)
- `docs/migrations.md` - Doctrine Migrations (`migrations/`): `antispam:db:upgrade` at boot (fresh / legacy schema:update install / migrated), every entity change needs a reviewed `doctrine:migrations:diff` migration
- `docs/scoring.md` - scoring pipeline, DNSBL, regex/wildcard patterns, rule ownership (per-mailbox vs global `*` rules)
- `docs/protection.md` - impersonation/BEC, link protection, attachment policy (web + agent)
- `docs/spam-handling.md` - where spam goes (move vs delete), quarantine semantics, retroactive blacklist, cron log (`antispam:cron:run`, `/cron/logs`)
- `docs/health.md` - health checks, public `/health` for uptime monitors, token-protected details + Prometheus `/metrics`, "Stan systemu" page, `antispam:health:check` alerts (e-mail/webhook)
- `docs/users.md` - users and roles (ROLE_ADMIN / ROLE_USER), mailbox ownership, legacy ADMIN_PASSWORD admin, `/my` area
- `docs/audit.md` - audit log ("Dziennik audytu", `/audit`): what is recorded, `AuditLogger` / `AuditTrait`, CSV export, `audit.retention_days`
- `docs/quarantine-digest.md` - end-user quarantine digest e-mail, signed `/q/` links, `antispam:digest:send`
- `docs/feed.md` - shared spam feed (centralized spam DB): fingerprints, API, sync
- `docs/feed-api.md` - shared spam feed HTTP API reference (endpoints, auth, examples)
- `docs/phishing.md` - phishing reports from the plugins: full message storage, `/phishing` analysis page, blocking, .eml export, forwarding to CERT Polska (cert@cert.pl) / SOC
- `docs/oauth.md` - OAuth2 (XOAUTH2) IMAP login for Microsoft 365 / Gmail: Entra / Google app registration, flows, socket IMAP client (`src/AntispamBundle/Imap/`), token refresh, limits, troubleshooting
- `docs/thunderbird.md` - Thunderbird plugin: spam reports, on-arrival checks, login, `/api/plugin`
- `docs/outlook.md` - Outlook add-in: hosting (HTTPS), sideload / admin deploy, task pane features and limits
- `docs/apple-mail.md` - Apple Mail MailKit extension: why source-only, layout, build/sign notes
- `docs/backup.md` - configuration backup/restore (`antispam:export` / `antispam:import`, panel `/backup`), secrets handling, `antispam:doctor` checks

## Tech stack
- PHP >= 8.2 (ext-imap, so not 8.4+), Symfony 7.4, Doctrine ORM 3 / DBAL 4 (PHP attributes mapping) + Doctrine Migrations, MySQL/MariaDB
- Symfony Mailer (`MAILER_DSN`), PHPUnit 11 (`vendor/bin/phpunit`)
- Settings: key/value `config` table via `AntispamBundle\Services\ConfigService` (formerly poznet/configbundle)
- ddeboer/imap (IMAP mode), phpseclib/phpseclib (SSH mode)
- Bootstrap 3 frontend (bundled in `Resources/public/vendor`) + custom theme `Resources/public/css/panel.css` (light/dark, Pancerna Panda brand colors, Montserrat + Open Sans), Twig templates
- UI language: Polish (`locale: pl`)
