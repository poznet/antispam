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
| Infected attachment (ClamAV) | `CheckAttachments` | clamav_score (def. 15) + forced spam |
| Flagged attachment (VirusTotal) | `CheckAttachmentsVirusTotal` | vt_score (def. 15) + forced spam |

Whitelists bypass all scoring (`stopPropagation()` on match).

## Attachment scanning (ClamAV)

When enabled, `CheckAttachments` streams every message attachment through a
ClamAV daemon (`clamd`) using the INSTREAM command. A malware hit adds the
configured `clamav_score` **and** marks the message as spam outright, so an
infected attachment is caught regardless of the other signals. Scanning runs
after DNSBL and before the final decision.

Scanning is **disabled by default** because it depends on a reachable `clamd`
instance. Configure it under **Settings → Spam Filter Settings → Attachment
Scanning**:

| Config key (`ConfigBundle`)   | Default                 | Meaning                                   |
|-------------------------------|-------------------------|-------------------------------------------|
| `scoring.clamav_enabled`      | `false`                 | Master switch for attachment scanning     |
| `scoring.clamav_dsn`          | `tcp://127.0.0.1:3310`  | clamd endpoint (see DSN forms below)      |
| `scoring.clamav_score`        | `15`                    | Score added on a malware hit              |
| `scoring.clamav_max_size`     | `26214400` (25 MiB)     | Attachments larger than this are skipped  |
| `scoring.clamav_timeout`      | `30`                    | Connect / read timeout in seconds         |

The DSN accepts a TCP endpoint (`tcp://host:port`, or the bare `host:port`
shorthand) or a local unix socket (`unix:///var/run/clamav/clamd.ctl`).

Resilience: if `clamd` is unreachable or returns an error, the scan is skipped
silently and the message is **not** penalised — a missing daemon never turns
ham into spam. Attachments above `clamav_max_size` are skipped rather than
truncated. The matched signature and filename are recorded in the score log
reasons as `clamav:<signature>`.

> Note: attachment scanning currently applies to the IMAP pipeline (web app).
> The standalone Maildir agent does not yet shell out to ClamAV.

## Attachment reputation (VirusTotal)

When enabled, `CheckAttachmentsVirusTotal` computes the SHA-256 of each
attachment and looks it up on the VirusTotal v3 API. If the number of engines
flagging the file as malicious reaches `vt_threshold`, the configured `vt_score`
is added **and** the message is marked as spam. This runs after ClamAV and
before the final decision.

**Privacy:** only the hash is sent to VirusTotal — never the attachment bytes.
A file VirusTotal has never seen (HTTP 404) is simply treated as "no opinion".

Scanning is **disabled by default** and requires an API key. Configure it under
**Settings → Spam Filter Settings → Attachment Reputation**:

| Config key (`ConfigBundle`) | Default | Meaning                                            |
|-----------------------------|---------|----------------------------------------------------|
| `scoring.vt_enabled`        | `false` | Master switch for VirusTotal lookups               |
| `scoring.vt_api_key`        | `''`    | VirusTotal API key (required)                      |
| `scoring.vt_threshold`      | `3`     | Min. engines flagging malicious before acting      |
| `scoring.vt_score`          | `15`    | Score added on a hit                               |
| `scoring.vt_timeout`        | `15`    | HTTP connect / read timeout in seconds             |

Resilience: an unknown hash, a rate-limit (HTTP 429), a rejected key, or any
network error is treated as "no opinion" and never penalises a message. The
free VirusTotal key is rate-limited to ~4 requests/minute, so this is best
suited to low-volume mailboxes or a paid key. The verdict and filename are
recorded in the score log reasons as `virustotal:<malicious>/<total>`.

Requires the PHP `curl` extension. Like ClamAV, this applies to the IMAP
pipeline only — the standalone Maildir agent does not call VirusTotal.

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
