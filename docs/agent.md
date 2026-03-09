# Maildir Agent

## Overview

The antispam agent is a standalone PHP script that runs directly on a hosting server, operating on Maildir folders without IMAP. It uses SQLite for storing filtering rules.

## Requirements

- PHP 7.1+ with SQLite3 extension
- Access to Maildir directory structure
- No Composer dependencies required

## Installation

1. Download `antispam-agent.php` from the web interface (Accounts > Download Agent)
2. Upload to your hosting server (e.g., `~/antispam-agent/`)
3. Or use automatic deploy from the web interface

## Commands

### Test environment
```bash
php antispam-agent.php test
```
Checks PHP version, SQLite3 extension, Maildir path, write permissions. Returns JSON.

### Import rules
```bash
echo '{"whitelist":[...],"blacklist":[...]}' | php antispam-agent.php import-rules
# or
php antispam-agent.php import-rules < rules.json
```
Imports filtering rules from JSON into local SQLite database.

### Scan mailbox
```bash
php antispam-agent.php scan
php antispam-agent.php scan --maildir=/home/user/Maildir
php antispam-agent.php scan --db=/home/user/antispam-agent/rules.sqlite
```
Scans Maildir for spam and moves matching messages to `.SPAM/` folder.

Output (JSON):
```json
{
  "total": 150,
  "checked": 120,
  "skipped": 30,
  "whitelisted": 45,
  "blacklisted": 12,
  "moved_to_spam": 12
}
```

## Maildir Structure

```
~/Maildir/
  new/          <- new unread messages
  cur/          <- read messages (flags in filename, e.g. :2,S)
  .SPAM/
    new/        <- spam (new)
    cur/        <- spam (read)
```

## SQLite Schema

```sql
CREATE TABLE whitelist (id INTEGER PRIMARY KEY, email TEXT, host TEXT);
CREATE TABLE email_whitelist (id INTEGER PRIMARY KEY, email TEXT, whitelistemail TEXT);
CREATE TABLE blacklist (id INTEGER PRIMARY KEY, email TEXT, host TEXT);
CREATE TABLE email_blacklist (id INTEGER PRIMARY KEY, email TEXT, blacklistemail TEXT);
CREATE TABLE checked (id INTEGER PRIMARY KEY, message_id TEXT UNIQUE);
```

## Rules JSON Format

```json
{
  "whitelist": [
    {"email": "user@example.com", "host": "trusted-domain.com"}
  ],
  "email_whitelist": [
    {"email": "user@example.com", "whitelistemail": "friend@example.com"}
  ],
  "blacklist": [
    {"email": "user@example.com", "host": "spam-domain.com"}
  ],
  "email_blacklist": [
    {"email": "user@example.com", "blacklistemail": "spammer@example.com"}
  ]
}
```
