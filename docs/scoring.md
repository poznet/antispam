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
**Ustawienia → Filtr spamu**.

**Per mailbox:** an account can override the spam threshold, the quarantine
threshold and the scoring switch (**Konta → Edytuj → Ustawienia skrzynki**,
empty = inherit). The effective value (account override -> global) applies to
everything that reads a threshold for that mailbox: the IMAP pipeline
(`classify()`/`decide()`), the header cap below, the CERT default score, the
plugin `/check`, the retroactive blacklist pass and the SSH agent (scan flags
and synced settings). The legacy mailbox always uses the global values. See
[accounts.md](accounts.md#per-mailbox-settings-ustawienia-skrzynki).

## Scoring signals

| Signal            | Listener              | Default score        |
|-------------------|-----------------------|----------------------|
| Domain blacklist  | `CheckBlacklist`      | rule.score (def. 10) |
| Email blacklist   | `CheckEmailBlacklist` | rule.score (def. 10) |
| SPF fail/softfail (`spf_fail`) | `CheckHeaders` | 6 (hard)        |
| DKIM fail, no passing signature (`dkim_fail`) | `CheckHeaders` | 4 (hard) |
| DMARC fail (`dmarc_fail`) | `CheckHeaders` | 6 (hard)             |
| No DKIM signature (`dkim_none`) | `CheckHeaders` | 1               |
| No DMARC policy (`dmarc_none`) | `CheckHeaders` | 1                |
| From/Reply-To mismatch | `CheckHeaders`   | 3                    |
| All-caps subject (≥ 10 letters, none lower-case) / money keywords / excess punctuation | `CheckHeaders` | 3 |
| Missing Message-ID| `CheckHeaders`        | 2                    |
| > 10 Received hops| `CheckHeaders`        | 2                    |
| Header score cap (`header_cap`, negative) | `CheckHeaders` | see below |
| DNSBL hit         | `CheckDnsbl`          | provider.score       |
| Infected attachment (ClamAV) | `CheckAttachments` | clamav_score (def. 15) + forced spam |
| Flagged attachment (VirusTotal) | `CheckAttachmentsVirusTotal` | vt_score (def. 15) + forced spam |
| Shared feed match (sender/body) | `CheckSharedFeed`     | feed.score (def. 6)  |
| Sender/link domain on the CERT Polska list (`cert_hole:<domain>`, off by default) | `CheckCertHole` | cert.score (def. = spam threshold); see [protection.md](protection.md#cert-polska-warning-list-cert_hole) |
| VIP display-name spoofing | `CheckImpersonation` | 8 |
| Lookalike sender domain | `CheckImpersonation` | 6 |
| Own-domain spoof (SPF/DMARC fail) | `CheckImpersonation` | 6 |
| Address in display name | `CheckImpersonation` | 3 |
| Link text / target mismatch, IP link, punycode link | `CheckUrls` | 3 each |
| URL shortener | `CheckUrls` | 2 |
| Link domain on URI block list | `CheckUrls` | zone score (def. 6) |
| Link flagged by Google Safe Browsing (opt-in) | `CheckUrls` | 10 |
| Blocked attachment type (also inside ZIP) | `CheckAttachmentPolicy` | 15 |
| Disguised executable | `CheckAttachmentPolicy` | 10 |
| Double extension / bidi filename | `CheckAttachmentPolicy` | 8 |
| Office macro / active PDF | `CheckAttachmentPolicy` | 6 |
| Password-protected archive / document | `CheckAttachmentPolicy` | 5 |
| Local Bayes classifier, `bayes:<p>` (off by default; only once trained) | `CheckBayes` | p ≥ 0.99: +5, p ≥ 0.90: +3, p ≤ 0.01: −2 (not for blacklisted senders); see [bayes.md](bayes.md) |

### Header checks (`HeaderAnalyzer`)

- SPF/DKIM/DMARC are read from the **topmost** `Authentication-Results` (and
  `Received-SPF`) header only - the one the receiving server added. Lower
  ones come from earlier hops or from the sender (a spammer can add its own
  `spf=pass`), and stale results of forwarded mail must not count.
- Folded headers are unfolded and the subject is RFC 2047-decoded before the
  heuristics. In IMAP mode the raw header block is fetched
  (`imap_fetchheader`); `imap_headerinfo()` has no authentication headers.
- `dkim=none` / `dmarc=none` (unsigned mail, no DMARC record - normal for
  many small senders) are worth **1 point** each. Until this release they
  were scored as failures (4 + 6 = 10 = the spam threshold), which made
  unsigned legitimate mail spam in the plugin scanner and the agent.
- **Cap:** the soft header signals together stay below the quarantine
  threshold, and the whole header score stays below the spam threshold.
  Headers alone can therefore quarantine a message (hard SPF/DKIM/DMARC
  failures) but never send it to SPAM - that needs more evidence (blacklist,
  DNSBL, links, attachments, feed...). The cut is logged as a negative
  `header_cap` reason, so the reasons still add up. With the defaults (5/10):
  soft ≤ 4, total ≤ 9. The caps follow the thresholds of the mailbox being
  scored (per-mailbox overrides included).

The Maildir agent has its own copy of these rules
(`analyzeHeaders()` in `antispam-agent.php`) and must follow the same defaults.

The impersonation, link and attachment-policy rules are described in
[protection.md](protection.md). Quarantined messages can be released by their
owners from the [quarantine digest](quarantine-digest.md).

Whitelists bypass all scoring (`stopPropagation()` on match).

The shared feed match scores incoming mail against fingerprints of spam caught
by this and other instances — see [feed.md](feed.md).

## Attachment scanning (ClamAV)

When enabled, `CheckAttachments` streams every message attachment through a
ClamAV daemon (`clamd`) using the INSTREAM command. A malware hit adds the
configured `clamav_score` **and** marks the message as spam outright, so an
infected attachment is caught regardless of the other signals. Scanning runs
after DNSBL and before the final decision.

Scanning is **disabled by default** because it depends on a reachable `clamd`
instance. Configure it under **Ustawienia → Filtr spamu → Skanowanie
załączników (ClamAV)**:

| Config key (`config` table)   | Default                 | Meaning                                   |
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

> Note: the standalone Maildir agent also supports ClamAV scanning — settings
> are pushed to it via the sync payload. See `docs/agent.md`.

## Attachment reputation (VirusTotal)

When enabled, `CheckAttachmentsVirusTotal` computes the SHA-256 of each
attachment and looks it up on the VirusTotal v3 API. If the number of engines
flagging the file as malicious reaches `vt_threshold`, the configured `vt_score`
is added **and** the message is marked as spam. This runs after ClamAV and
before the final decision.

**Privacy:** only the hash is sent to VirusTotal — never the attachment bytes.
A file VirusTotal has never seen (HTTP 404) is simply treated as "no opinion".

Scanning is **disabled by default** and requires an API key. Configure it under
**Ustawienia → Filtr spamu → Reputacja załączników (VirusTotal)**:

| Config key (`config` table) | Default | Meaning                                            |
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
Verdicts are kept per hash for the rest of the run (up to 1000 hashes, errors
are not kept), so an attachment repeated in many messages costs one lookup.

Requires the PHP `curl` extension. The standalone Maildir agent supports the
same VirusTotal lookup; settings are pushed to it via the sync payload (see
`docs/agent.md`).

## Pattern types

Blacklist and whitelist rules support three pattern types:

- `exact` — case-insensitive equality (default, backwards compatible)
- `wildcard` — shell-style globs: `*.example.com`, `*@*.ru`, `mail?.evil`
- `regex` — PHP PCRE without delimiters, e.g. `^mail\d+\.bad$`

Invalid regex is logged to the error log and simply never matches — a bad rule
won't crash the scan. Regex rules run with `pcre.backtrack_limit` lowered to
100 000, so a catastrophic pattern such as `(a+)+$` stops matching instead of
stalling the scan; `PatternMatcher::validate()` reports invalid and too
expensive regexes for the rule forms. Wildcards escape every regex
metacharacter, including the `~` delimiter.

All rules are matched against the **From:** address (domain rules: its
domain), never the `Sender:` header.

## Rule ownership

Every white/blacklist rule (`antispam_whitelist`, `antispam_email_whitelist`,
`antispam_blacklist`, `antispam_email_blacklist`) has an owner in its
`email` column (`VARCHAR(255) NOT NULL`, unchanged):

| `email` value | Applies to |
|---------------|------------|
| a mailbox address (an account's e-mail, or the legacy mailbox from Ustawienia → E-mail) | that mailbox only |
| `*` (`RuleOwnership::ALL`, shown as **Wszystkie skrzynki**) | every mailbox: all IMAP and SSH accounts and the legacy mailbox |

`*` was chosen over `NULL` because it keeps the column NOT NULL (no schema
change), is never a valid address, and works in a plain `IN (...)` lookup.

End users (`ROLE_USER`) can add and delete rules owned by their own mailboxes on
**Moje reguły** (`/my/rules`) - exact and wildcard only, never `*`; see
[users.md](users.md#own-sender-rules-myrules).
Every consumer loads the rules of a mailbox with
`findBy(['email' => RuleOwnership::scope($mailbox)])`, i.e. `IN ($mailbox, '*')`:
the scan listeners (`CheckWhitelist`, `CheckEmailWhitelist`, `CheckBlacklist`,
`CheckEmailBlacklist`), the plugin's `RawMessageScanner`, the agent rules
export (`AgentRulesExporter` - the agent gets its account's rules plus the
global ones) and the retroactive pass (`RetroactiveSpamService`: a global
blacklist rule is applied to every account and the legacy mailbox, and the
whitelists checked there include the global ones).

Panel forms (**Whitelista / Blacklista domen / e-mail**, **Import / eksport**)
have a mailbox selector with **Wszystkie skrzynki**, the legacy mailbox (when
its e-mail is set) and every account e-mail; the legacy mailbox is
preselected when configured (what panel rules always got), otherwise
**Wszystkie skrzynki** - so an install without a legacy mailbox can still add
rules. The submitted owner must be one of those choices. The lists show the
owner of every rule and can be filtered by owner (`?owner=`); owners that no
longer exist (deleted account, changed legacy address) are shown as
*nieaktywna* - such rules apply nowhere, delete and re-add them.

Rules created elsewhere keep their own owner: plugin reports, phishing
"Zablokuj" and the quarantine *Zawsze akceptuj* use the account's e-mail.

**Dedupe** is per owner: the same value may be added for two mailboxes, but
not twice for one mailbox, and a mailbox rule is skipped when an identical
global rule exists (a global rule can still be added next to mailbox rules).
Comparison is case-insensitive (the MySQL collation; bulk import lowercases
exact/wildcard values). There is deliberately **no unique index** on
`(email, value)`: adding one needs a migration that runs on every install
([migrations.md](migrations.md)), and an existing install may already hold duplicates (plugin/phishing
rules are deduped per pattern type only, double submits), which would make
the index creation - and the container start - fail; a 255+255 character
utf8mb4 key would also exceed the 767-byte limit of legacy row formats.

## DNSBL integration

Configure DNS block lists under **Blacklisty → Dostawcy DNSBL**. Each zone
has its own score and per-IP cache TTL. Presets include Spamhaus, SORBS,
Barracuda, SpamCop, PSBL and UCEPROTECT — click "Add" to enable them. You can
also add any custom zone.

The listener takes the connecting IP from the raw `Received` headers: top-down,
the first public IPv4 in a `from` clause (bracketed `[a.b.c.d]` preferred; the
`by` part, private, loopback and reserved addresses are skipped). The plugin
scanner uses the same extractor (`RawMessageParser::connectingIpFromReceived()`).

Only an answer in `127.0.0.0/8` counts as **listed** - except `127.0.0.1`
(URIBL & co.: query refused) and `127.255.255.0/24` (Spamhaus error codes,
e.g. queries through a public resolver, typical in Docker). Any other answer
(ISP resolvers answering NXDOMAIN with their own IP) and DNS errors mean "not
listed" and are **not cached**; cache rows written as "listed" with a
non-listing response by older versions are dropped and queried again. Real
answers are cached (`antispam_dnsbl_cache`) for the provider's TTL. A zone
whose lookups fail or take over 3 s three times is skipped for the rest of
the run (circuit breaker; the URI DBL lookups in `CheckUrls` use the same
rule). Provider hit counters are incremented in SQL.

The same configuration is synced down to the Maildir agent during
`antispam:agent:sync` — the standalone agent performs DNSBL lookups locally.

## Score log

Every processed message (when `scoring.log_enabled = true`) appends a row to
`antispam_spam_score_log` with the score, the decision and a JSON array of
reasons. Browse it under **Mailboxes → Score Log** to audit "why was this
flagged".

### First scan of a new mailbox

The first scan after a mailbox is connected (`Account.lastScanAt` still null)
works through the whole existing INBOX backlog, so it is kept out of the
numbers: messages are scored and moved as usual, but their log rows get
`initial_scan = 1` and are skipped by `statsByDecision()` / `dailyCounts()`
(dashboard tiles, 14-day chart, Spambox stats), rule hit counters
(`counter` on white/blacklists, "top blacklist" on the dashboard) are not
bumped, and the scan result is stored with `"initial": true` so it does not
show in the dashboard's "Ostatnie skany". The rows stay visible in the score
log, marked "pierwszy skan". SSH accounts only get the `initial` result flag
(the agent scores on the server and does not write the score log).

## Agent CLI flags

```
php antispam-agent.php scan \
    --maildir=~/Maildir \
    --db=/path/to/rules.sqlite \
    --spam-threshold=10 \
    --quarantine-threshold=5 \
    [--no-dnsbl] [--no-headers] [--no-impersonation] [--no-urls] \
    [--no-attachment-policy] [--no-clamav] [--no-virustotal]

php antispam-agent.php health --maildir=~/Maildir --db=/path/to/rules.sqlite
```

## Schema changes

The following columns / tables were added in 1.x (by `doctrine:schema:update` at
the time; they are part of the baseline migration now, and `antispam:db:upgrade`
adds them to an older install):

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
