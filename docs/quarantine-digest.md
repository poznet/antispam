# Quarantine Digest

Inspired by Barracuda's quarantine notifications. Each mailbox owner gets a
periodic e-mail (in Polish) listing newly quarantined messages, each with
one-click actions:

| Button | Effect |
|--------|--------|
| **Dostarcz** (Deliver) | Moves the message back to INBOX |
| **Zawsze akceptuj** (Always accept) | Delivers it and adds an exact e-mail whitelist rule for the sender |
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
| `imap` | Legacy IMAP account (Settings → Legacy Account Config), folder `QUARANTINE` | *Recipient for the legacy IMAP mailbox*, or the configured IMAP e-mail |
| `ssh-<id>` | Every SSH account with a deployed agent, `~/Maildir/.QUARANTINE` | The account e-mail |

**Which messages are listed:** those received since the previous successful digest
for that mailbox (on the first run, the last 24 hours), newest first, up to
*Max messages per digest*. The rest are counted and the e-mail says how many more
there are. Mailboxes with nothing new are skipped and get no e-mail.

**Reasons:** each entry shows up to three human-readable reasons from the score log
(e.g. "Domena nadawcy łudząco podobna do Twojej"). For the SSH agent the link is
exact (`score_log.file`). For IMAP the newest quarantine decision with the same
sender and subject is used.

## Security

- **Signed tokens.** `base64url(json) . base64url(HMAC-SHA256)` keyed with the
  application secret (`APP_SECRET` / `secret`). A token encodes the mailbox, message
  id, action and expiry, plus sender and subject for the confirmation page. It is
  valid for *Link validity* days (default 7). Changing `APP_SECRET` invalidates
  every link already sent.
- **Default secret = disabled.** While `secret` still has one of the placeholder
  values shipped in this repository, the digest refuses to send and `/q/` rejects
  every token, because anyone could forge one.
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

`/q/` is the only anonymous route besides `/login` and `/api/feed`
(`app/config/security.yml`).

## Configuration

**Settings → Quarantine Digest** (`/config/digest/`):

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

Mail goes through the application's Swiftmailer transport (`MAILER_*` environment
variables / `mailer_*` parameters). Send from an address whose SPF/DKIM is set up for
that transport, or the digest itself may be filtered.

## Scheduling

```bash
# daily at 07:00
0 7 * * * php bin/console antispam:digest:send
```

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
