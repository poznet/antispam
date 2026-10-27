# Antispam Pancernapanda

Symfony 7.4 LTS application for email spam filtering via IMAP or SSH+Maildir agent. Part of the Pancernapanda security toolkit.

## Project structure
- `src/AntispamBundle/` - main bundle (entities, controllers, services, commands, event listeners)
- `src/Kernel.php` - MicroKernel; `config/` - bundles, packages (`*.yaml`), routes, `services.yaml` (autowiring + listener priorities)
- `public/` - web root (`index.php` front controller); `var/` - cache, logs, `var/data` (checked-message markers)
- `.env` - default env vars (override in `.env.local`; Docker freezes them into `.env.local.php`)
- `src/AntispamBundle/Resources/agent/` - standalone Maildir agent PHP script
- `src/AntispamBundle/Resources/thunderbird/` - Thunderbird plugin (MailExtension), served as .xpi by `/plugin/download`
- `landing/` - static marketing page for antispam.pancernapanda.pl (plain HTML/CSS/JS, see `landing/README.md`)

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
- `docs/deployment.md` - Docker / Coolify deployment guide
- `docs/scoring.md` - scoring pipeline, DNSBL, regex/wildcard patterns
- `docs/protection.md` - impersonation/BEC, link protection, attachment policy (web + agent)
- `docs/quarantine-digest.md` - end-user quarantine digest e-mail, signed `/q/` links, `antispam:digest:send`
- `docs/feed.md` - shared spam feed (centralized spam DB): fingerprints, API, sync
- `docs/feed-api.md` - shared spam feed HTTP API reference (endpoints, auth, examples)
- `docs/thunderbird.md` - Thunderbird plugin: spam reports, on-arrival checks, login, `/api/plugin`

## Tech stack
- PHP >= 8.2 (ext-imap, so not 8.4+), Symfony 7.4, Doctrine ORM 3 / DBAL 4 (PHP attributes mapping), MySQL/MariaDB
- Symfony Mailer (`MAILER_DSN`), PHPUnit 11 (`vendor/bin/phpunit`)
- Settings: key/value `config` table via `AntispamBundle\Services\ConfigService` (formerly poznet/configbundle)
- ddeboer/imap (IMAP mode), phpseclib/phpseclib (SSH mode)
- Bootstrap 3 frontend (bundled in `Resources/public/vendor`) + custom theme `Resources/public/css/panel.css` (light/dark, Pancerna Panda brand colors, Montserrat + Open Sans), Twig templates
- UI language: Polish (`locale: pl`)
