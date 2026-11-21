Antispam Pancernapanda
======================

Symfony-based application for cleaning spam from email accounts via IMAP or SSH+Maildir. Part of the Pancernapanda security toolkit.

## Requirements

- **PHP 8.2 or 8.3** (`ext-imap` is not bundled with PHP 8.4+)
- **Symfony 7.4 LTS**, Doctrine ORM 3
- **MySQL 5.7+** or MariaDB 10.4+
- PHP extensions: `imap`, `pdo_mysql`, `iconv`, `ctype`, `curl`, `intl`, `zip`
- Mailboxes: IMAP (password or OAuth2 for Microsoft 365 / Gmail) or SSH access to a Maildir hosting account

## Features

- **Many mailboxes**: IMAP accounts (password or OAuth2) and SSH+Maildir accounts with a standalone agent ([docs/accounts.md](docs/accounts.md), [docs/agent.md](docs/agent.md))
- **Scoring**: whitelists / blacklists (exact, wildcard, regex), DNSBL, header and SPF/DKIM/DMARC checks, optional Bayes classifier, ClamAV / VirusTotal, complex AND / OR / NOT rules ([docs/scoring.md](docs/scoring.md))
- **SPAM folder and quarantine** per mailbox in the panel: preview, release (without the SPAM tag, original date), release a whole domain, retroactive blacklist, full rescan ([docs/spam-handling.md](docs/spam-handling.md))
- **Users and roles**: admins and mailbox owners (`/my`), 2FA (TOTP) and YubiKey ([docs/users.md](docs/users.md))
- **Background jobs, health checks, audit log, backups** ([docs/jobs.md](docs/jobs.md), [docs/health.md](docs/health.md), [docs/audit.md](docs/audit.md), [docs/backup.md](docs/backup.md))
- **Impersonation / BEC protection**: VIP display-name spoofing, lookalike and homoglyph domains, own-domain spoofing
- **Link protection**: text/target mismatch, IP and shortened links, punycode, URI block lists, Google Safe Browsing
- **Attachment policy**: blocked file types (also inside ZIP), double extensions, disguised executables, macros, encrypted archives
- **Quarantine digest**: periodic e-mail to mailbox owners with signed one-click deliver / always-accept / delete links
- **Mail client plugins**: Thunderbird and Outlook — report spam / phishing, check a message, on-arrival checks ([docs/thunderbird.md](docs/thunderbird.md), [docs/outlook.md](docs/outlook.md))

## Installation

```bash
# Clone repository
git clone https://github.com/poznet/antispam.git
cd antispam

# Configure: override the defaults from .env in .env.local (not committed)
cat > .env.local <<'ENV'
APP_SECRET=<random string, e.g. openssl rand -hex 32>
DATABASE_HOST=127.0.0.1
DATABASE_PASSWORD=<password>
ADMIN_PASSWORD_HASH='<output of: php bin/console security:hash-password>'
MAILER_DSN=smtp://user:pass@smtp.example.com:587
ENV

# Install dependencies (also clears the cache and publishes bundle assets)
composer install

# Create database
php bin/console doctrine:database:create
php bin/console antispam:db:upgrade   # Doctrine Migrations, docs/migrations.md
```

Point the web server's document root at `public/`.

### Docker / Coolify

A production-ready Docker stack is included (`Dockerfile`, `docker-compose.yml`).
See [docs/deployment.md](docs/deployment.md) for step-by-step instructions on
deploying the app on Coolify or plain docker-compose.

## Usage

Mailboxes are added in the panel (*Konta*). Scans, syncs and the other periodic
tasks run from the Docker `scheduler` service (`docker/scheduler.sh`); without
Docker, run them from cron - full list in [docs/commands.md](docs/commands.md).

### Check the install
```bash
php bin/console antispam:doctor
```

### Run spam filtering (every mailbox)
```bash
php bin/console antispam:agent:scan-all
php bin/console antispam:jobs:work      # background jobs started from the panel
```

### Web interface
Point a web server at `public/` (or run `php -S 127.0.0.1:8000 -t public public/index.php`
for local development) and log in with `ADMIN_USER` / the password behind `ADMIN_PASSWORD_HASH`.

### Tests
```bash
vendor/bin/phpunit
```

## Upgrade

Upgrading an old Symfony 4.4 installation: see [UPGRADE.md](UPGRADE.md). Releases and changes: [CHANGELOG.md](CHANGELOG.md).

## Status

In production use, actively developed; the version is `AntispamBundle\AppVersion::VERSION` ([CHANGELOG.md](CHANGELOG.md)).

## License

Proprietary
