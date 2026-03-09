# Antispam

Symfony 4.4 application for email spam filtering via IMAP or SSH+Maildir agent.

## Project structure
- `src/AntispamBundle/` - main bundle (entities, controllers, services, commands, event listeners)
- `app/` - Symfony app config (config.yml, routing.yml, parameters.yml)
- `web/` - public web root
- `src/AntispamBundle/Resources/agent/` - standalone Maildir agent PHP script

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

## Tech stack
- PHP >= 7.1.3, Symfony 4.4, Doctrine ORM, MySQL
- ddeboer/imap (IMAP mode), phpseclib/phpseclib (SSH mode)
- Bootstrap 3 frontend, Twig templates
