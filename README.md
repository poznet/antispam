Antispam
========

A Symfony based application for cleaning spam from email accounts using IMAP protocol.

[![Build Status](https://travis-ci.org/poznet/antispam.svg?branch=master)](https://travis-ci.org/poznet/antispam)   [![SensioLabsInsight](https://insight.sensiolabs.com/projects/6fb908c6-493c-4754-b04d-c04953c537d7/mini.png)](https://insight.sensiolabs.com/projects/6fb908c6-493c-4754-b04d-c04953c537d7)

## Requirements

- **PHP >= 7.2.5** (recommended: 7.4, 8.0, or 8.1)
- **Symfony 5.4 LTS**
- **MySQL 5.7+** or MariaDB 10.2+
- **ext-iconv**
- **ext-ctype**
- IMAP enabled email account

## Features

- **Email filtering** via IMAP protocol
- **Whitelist/Blacklist management** for domains and email addresses
- **Automatic spam detection** using configurable rules
- **Event-driven architecture** for flexible message processing
- **CLI commands** for batch processing
- **Web interface** for managing filters
- **Statistics tracking** with counter for each rule

## Installation

```bash
# Clone repository
git clone https://github.com/poznet/antispam.git
cd antispam

# Install dependencies
composer install

# Configure database and email settings
cp app/config/parameters.yml.dist app/config/parameters.yml
# Edit app/config/parameters.yml with your settings

# Create database
php bin/console doctrine:database:create
php bin/console doctrine:schema:create
```

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
Access the web interface at `http://localhost/app_dev.php` to manage whitelists and blacklists.

## Upgrade

If upgrading from Symfony 2.8, see [UPGRADE.md](UPGRADE.md) for detailed instructions.

## Status

**Pre-alpha stage** - Active development

## License

Proprietary
