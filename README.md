Antispam Pancernapanda
======================

Symfony-based application for cleaning spam from email accounts via IMAP or SSH+Maildir. Part of the Pancernapanda security toolkit.

## Requirements

- **PHP 8.2 or 8.3** (`ext-imap` is not bundled with PHP 8.4+)
- **Symfony 7.4 LTS**, Doctrine ORM 3
- **MySQL 5.7+** or MariaDB 10.4+
- PHP extensions: `imap`, `pdo_mysql`, `iconv`, `ctype`, `curl`, `intl`, `zip`
- IMAP enabled email account

## Features

- **Email filtering** via IMAP protocol
- **Whitelist/Blacklist management** for domains and email addresses
- **Automatic spam detection** using configurable rules
- **Event-driven architecture** for flexible message processing
- **CLI commands** for batch processing
- **Web interface** for managing filters
- **Statistics tracking** with counter for each rule
- **Impersonation / BEC protection**: VIP display-name spoofing, lookalike and homoglyph domains, own-domain spoofing
- **Link protection**: text/target mismatch, IP and shortened links, punycode, URI block lists, Google Safe Browsing
- **Attachment policy**: blocked file types (also inside ZIP), double extensions, disguised executables, macros, encrypted archives
- **Quarantine digest**: periodic e-mail to mailbox owners with signed one-click deliver / always-accept / delete links
- **Thunderbird plugin** — report spam from the mail client (no login needed) and, when logged in, have new mail checked by antispam on arrival ([docs/thunderbird.md](docs/thunderbird.md))

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

### Check configuration
```bash
php bin/console antispam:check
```

### Run spam filtering
```bash
php bin/console antispam:go
```

### Web interface
Point a web server at `public/` (or run `php -S 127.0.0.1:8000 -t public public/index.php`
for local development) and log in with `ADMIN_USER` / the password behind `ADMIN_PASSWORD_HASH`.

### Tests
```bash
vendor/bin/phpunit
```

## Upgrade

Upgrading an existing Symfony 4.4 installation: see [UPGRADE.md](UPGRADE.md).

## Status

**Pre-alpha stage** - Active development

## License

Proprietary
