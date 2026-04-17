# Spam Scoring Pipeline

The scoring pipeline turns a stream of yes/no rule checks into a single score
per message, then makes a final decision:

| Score                | Decision     | Action                               |
|----------------------|--------------|---------------------------------------|
| `< quarantine`       | ham          | leave in INBOX                        |
| `>= quarantine`      | quarantine   | move to QUARANTINE folder             |
| `>= spam`            | spam         | move to SPAM (or delete if enabled)   |
| whitelist hit        | whitelisted  | short-circuit, never scored           |

Defaults: `quarantine_threshold = 5`, `spam_threshold = 10`. Configure under
**Settings → Spam Filter Settings**.

## Scoring signals

| Signal            | Listener              | Default score        |
|-------------------|-----------------------|----------------------|
| Domain blacklist  | `CheckBlacklist`      | rule.score (def. 10) |
| Email blacklist   | `CheckEmailBlacklist` | rule.score (def. 10) |
| SPF fail          | `CheckHeaders`        | 6                    |
| DKIM fail/none    | `CheckHeaders`        | 4                    |
| DMARC fail/none   | `CheckHeaders`        | 6                    |
| From/Reply-To mismatch | `CheckHeaders`   | 3                    |
| All-caps subject / money keywords / excess punctuation | `CheckHeaders` | 3 |
| Missing Message-ID| `CheckHeaders`        | 2                    |
| > 10 Received hops| `CheckHeaders`        | 2                    |
| DNSBL hit         | `CheckDnsbl`          | provider.score       |

Whitelists bypass all scoring (`stopPropagation()` on match).

## Pattern types

Blacklist and whitelist rules support three pattern types:

- `exact` — case-insensitive equality (default, backwards compatible)
- `wildcard` — shell-style globs: `*.example.com`, `*@*.ru`, `mail?.evil`
- `regex` — PHP PCRE without delimiters, e.g. `^mail\d+\.bad$`

Invalid regex is logged to the error log and simply never matches — a bad rule
won't crash the scan.

## DNSBL integration

Configure DNS block lists under **Blacklists → DNSBL Providers**. Each zone
has its own score and per-IP cache TTL. Presets include Spamhaus, SORBS,
Barracuda, SpamCop, PSBL and UCEPROTECT — click "Add" to enable them. You can
also add any custom zone.

The listener reads the sender IP from the last `Received` header and queries
each enabled zone. Results are cached (`antispam_dnsbl_cache`) to avoid
hammering DNS.

The same configuration is synced down to the Maildir agent during
`antispam:agent:sync` — the standalone agent performs DNSBL lookups locally.

## Score log

Every processed message (when `scoring.log_enabled = true`) appends a row to
`antispam_spam_score_log` with the score, the decision and a JSON array of
reasons. Browse it under **Mailboxes → Score Log** to audit "why was this
flagged".

## Agent CLI flags

```
php antispam-agent.php scan \
    --maildir=~/Maildir \
    --db=/path/to/rules.sqlite \
    --spam-threshold=10 \
    --quarantine-threshold=5 \
    [--no-dnsbl] [--no-headers]

php antispam-agent.php health --maildir=~/Maildir --db=/path/to/rules.sqlite
```

## Schema changes

The following columns / tables are new and must be created via
`bin/console doctrine:schema:update --force` (or equivalent migration):

```sql
-- existing rule tables gain:
ALTER TABLE antispam_whitelist ADD pattern_type VARCHAR(16) NOT NULL DEFAULT 'exact';
ALTER TABLE antispam_email_whitelist ADD pattern_type VARCHAR(16) NOT NULL DEFAULT 'exact';
ALTER TABLE antispam_blacklist ADD pattern_type VARCHAR(16) NOT NULL DEFAULT 'exact';
ALTER TABLE antispam_blacklist ADD score INT NOT NULL DEFAULT 10;
ALTER TABLE antispam_email_blacklist ADD pattern_type VARCHAR(16) NOT NULL DEFAULT 'exact';
ALTER TABLE antispam_email_blacklist ADD score INT NOT NULL DEFAULT 10;

-- new tables:
CREATE TABLE antispam_dnsbl_provider (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    zone VARCHAR(255) NOT NULL UNIQUE,
    score INT NOT NULL DEFAULT 5,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    hits INT NOT NULL DEFAULT 0,
    cache_ttl INT NOT NULL DEFAULT 3600
);

CREATE TABLE antispam_dnsbl_cache (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    zone VARCHAR(255) NOT NULL,
    listed TINYINT(1) NOT NULL,
    response VARCHAR(64),
    checked_at DATETIME NOT NULL,
    INDEX idx_ip_zone (ip, zone)
);

CREATE TABLE antispam_spam_score_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_email VARCHAR(255),
    sender VARCHAR(255),
    subject VARCHAR(512),
    score INT NOT NULL,
    decision VARCHAR(16) NOT NULL,
    reasons TEXT,
    scored_at DATETIME NOT NULL,
    INDEX idx_account_email (account_email),
    INDEX idx_scored_at (scored_at)
);
```
