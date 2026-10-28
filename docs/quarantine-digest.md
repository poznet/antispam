# Quarantine Digest

Inspired by Barracuda's quarantine notifications. Each mailbox owner gets a
periodic e-mail (in Polish) listing newly quarantined messages, each with
one-click actions:

| Button | Effect |
|--------|--------|
| **Przywróć** (Restore) | Moves the message back to INBOX |
| **Zawsze akceptuj** (Always accept) | Restores it to INBOX and adds an exact e-mail whitelist rule for the sender |
| **Usuń** (Delete) | Deletes the message permanently |

Users can recover false positives themselves, without logging in or calling support.

## How it works

```
cron ─► antispam:digest:send
          └─ QuarantineDigestService
               ├─ QuarantineService::getMailboxes()   imap + every deployed SSH account
               ├─ QuarantineService::listItems()      IMAP QUARANTINE folder / agent quarantine-list
               ├─ DigestTokenService::create()        signed, expiring link per action
               └─ Swift_Mailer                         HTML + plain-text e-mail

recipient clicks link ─► GET  /q/{token}   confirmation page (nothing happens yet)
                     └─► POST /q/{token}   QuarantineService::release() / delete()
```

**Mailboxes**

| Key | Source | Recipient |
|-----|--------|-----------|
| `imap` | Legacy IMAP account (Ustawienia → Konfiguracja (stara)), folder `QUARANTINE` | *Recipient for the legacy IMAP mailbox*, or the configured IMAP e-mail |
| `imap-<id>` | Every IMAP account (Konta), folder `QUARANTINE` | *Odbiorca raportu* of the account, else the account e-mail |
| `ssh-<id>` | Every SSH account with a deployed agent, `~/Maildir/.QUARANTINE` | *Odbiorca raportu* of the account, else the account e-mail |

**Which messages are listed:** those received since the previous successful digest
for that mailbox (on the first run, the last 24 hours), newest first, up to
*Max messages per digest*. "Received" is the server's arrival time: IMAP
INTERNALDATE (`SEARCH SINCE` plus an exact cut-off), the file mtime for Maildir -
never the sender-controlled `Date:` header. The rest are counted and the e-mail
says how many more there are. Mailboxes with nothing new are skipped and get no e-mail.

**Reasons:** each entry shows up to three human-readable reasons from the score log
(e.g. "Domena nadawcy łudząco podobna do Twojej"). For the SSH agent the link is
exact (`score_log.file`). For IMAP the newest quarantine decision **of the same
mailbox** (`account_email`) with the same sender and subject is used (one query per
listing, index `idx_account_sender`; subjects are compared with the 500-character
clip of the log, older 500-byte clipped rows match too).

**No score log row = high risk (fail closed).** When no row is found (logging
disabled with `scoring.log_enabled`, row purged by `antispam:purge`, or the agent
has no `score_log` entry), the entry gets the synthetic reason `score_unknown`
("Brak zapisanej oceny - zachowaj ostrożność"). It counts as high risk, so neither
the digest nor `/my/quarantine` / `/spambox/quarantine` offers **Zawsze akceptuj**
for it. Deliver and Delete still work. With score logging turned off, IMAP
quarantine entries therefore never get the whitelist button.

## Security

- **Signed tokens.** `base64url(json) . base64url(HMAC-SHA256)` keyed with the
  application secret (`APP_SECRET` / `secret`). A token encodes the mailbox, message
  id, action and expiry, plus sender and subject for the confirmation page. It is
  valid for *Link validity* days (default 7). Changing `APP_SECRET` invalidates
  every link already sent.
- **IMAP links are bound to UIDVALIDITY.** An IMAP message id is a UID, and UIDs
  are only unique within one UIDVALIDITY of the folder (a recreated / restored
  `QUARANTINE` folder starts again and reuses them). IMAP tokens therefore carry
  the folder's UIDVALIDITY (`u`), and release / delete refuse to act ("Nie
  znaleziono wiadomości…") when the folder's current UIDVALIDITY differs. IMAP
  tokens **without** it - links in digests sent before this check existed - are
  rejected as invalid: they could act on whatever message now has that UID, and
  they expire within the link validity anyway (the quarantine stays available on
  `/my/quarantine`). SSH (Maildir) ids are unique file names and need no binding.
- **Default secret = disabled.** While `secret` still has one of the placeholder
  values shipped in this repository, looks like one ("change me", "not so
  secret"), or is shorter than 16 characters, the digest refuses to send and `/q/`
  rejects every token, because anyone could forge one.
- **GET never acts.** Mail gateways and link scanners (Barracuda, Defender Safe
  Links, …) pre-fetch URLs. Opening a link only shows a confirmation page, and the
  action runs on the POST from its button.
- **No whitelisting of high-risk mail.** Messages flagged for impersonation, a
  lookalike domain, own-domain spoofing, an attachment policy hit, malware or a
  blocklisted / Safe Browsing link get no "Always accept" button. No whitelist token
  is created for them, so the action cannot be invoked at all. These entries carry a
  fraud warning.
- `/q/` responses send `Cache-Control: no-store`, `Referrer-Policy: no-referrer` and
  `X-Robots-Tag: noindex`.
- Failed agent calls show a generic message. Raw agent output never reaches the
  public page.
- A released message is marked as checked, so the next scan won't quarantine it
  again.

`/q/` is the only anonymous route besides the home page `/`, `/login` and `/api/feed`
(`config/packages/security.yaml`).

## Configuration

**Ustawienia → Raport kwarantanny** (`/config/digest/`):

| Setting | Config key | Default |
|---------|------------|---------|
| Enable quarantine digest | `digest.enabled` | off |
| Public base URL (links point to `<base>/q/…`) | `digest.base_url` | *(required)* |
| Sender address / name | `digest.from_email`, `digest.from_name` | *(required)* / "Pancernapanda antispam" |
| Recipient for the legacy IMAP mailbox | `digest.imap_recipient` | IMAP e-mail |
| Link validity (days, 1–30) | `digest.token_ttl_days` | 7 |
| Max messages per digest (1–500) | `digest.max_items` | 50 |

The page lists every mailbox with its recipient and last digest time, offers a
**Preview** of the e-mail (last 7 days) and a **Save & send now** button. The last
send time per mailbox is stored as `digest.last_sent.<key>`.

Mail goes through Symfony Mailer (`MAILER_DSN` environment
variable). Send from an address whose SPF/DKIM is set up for
that transport, or the digest itself may be filtered.

## Per-mailbox settings

Each account (not the legacy mailbox) can override three digest settings on
**Konta → Edytuj → Ustawienia skrzynki**; empty = inherit:

| Setting | Column | Inherit = | Effect |
|---------|--------|-----------|--------|
| Raport kwarantanny | `digest_enabled` | `digest.enabled` | *wyłączony*: the mailbox gets no digest (status `disabled`, also with `--force` / *Zapisz i wyślij teraz*); *włączony*: it gets one even while the global switch is off (the command then runs for such mailboxes only) |
| Odbiorca raportu | `digest_recipient` | account e-mail | e.g. a department head; links in it act on that mailbox's quarantine |
| Godzina wysyłki | `digest_hour` | global schedule | the mailbox is sent at the first run at or after HH:00 (server time) that has not sent it yet today; earlier runs report `not-due` |

Precedence: account override -> global setting (`MailboxSettingsResolver`,
rows of `QuarantineService::getMailboxes()` carry `recipient`,
`digest_enabled` - the mailbox's own value or null - and `digest_hour`). The
mailbox table on **Raport kwarantanny** shows the overrides. Digests are
Polish only, so there is no per-mailbox language.

## Scheduling

```bash
# daily at 07:00
0 7 * * * php bin/console antispam:digest:send
# mailboxes with their own send hour: every other hour, only those
0 0-6,8-23 * * * php bin/console antispam:digest:send --scheduled-only
```

The daily run sends every mailbox without its own hour plus those whose hour
has come; `--scheduled-only` looks at mailboxes with their own hour only and
prints nothing else, so the hourly run is cheap. Without per-mailbox hours the
second line is not needed. The Docker scheduler does both (`DIGEST_HOUR`, see
[deployment.md](deployment.md)). Do not run both at the same hour - two
parallel runs could send a due mailbox twice.

See [commands.md](commands.md#antispamdigestsend) for options (`--dry-run`,
`--mailbox`, `--since`, `--force`).

## Agent commands used

```bash
php antispam-agent.php quarantine-list    --maildir=~/Maildir [--since=<unix-ts>] [--limit=200]
php antispam-agent.php quarantine-release --maildir=~/Maildir --id=<maildir-id> [--whitelist]
php antispam-agent.php quarantine-delete  --maildir=~/Maildir --id=<maildir-id>
```

See [agent.md](agent.md#quarantine-management). Agents deployed before this
feature must be **re-deployed** (Accounts → Deploy) to support the digest.
