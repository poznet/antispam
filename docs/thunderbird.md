# Thunderbird plugin

A Thunderbird MailExtension (Thunderbird 115+) that connects a user's mail
client to antispam. Source: `src/AntispamBundle/Resources/thunderbird/`.
Server side: `PluginApiController`, `PluginService`, `RawMessageScanner`,
`RawMessageParser`.

## Two modes

| | Not logged in | Logged in (mailbox e-mail + password) |
|---|---|---|
| Mark as spam (junk button, toolbar button, context menu) | ✔ — sender + body fingerprints go to the shared spam DB | ✔ — fingerprints **and** the sender is added to the account's e-mail blacklist (exact whitelist entry removed) |
| Mark as not spam | — | ✔ — exact blacklist entry removed, sender whitelisted for the account |
| Check new mail on arrival | — | ✔ — each new message in the matching mailbox is sent to antispam and marked / moved according to the decision |
| Manual "Check in antispam" | — | ✔ |

Anonymous reports only ever add fingerprints (`antispam_shared_spam_signal`,
origin `local`); how much they weigh is controlled by the shared feed's
*minimum reports* setting (see [feed.md](feed.md)). Fingerprints are recorded
even when the feed itself is disabled, so the data is ready once it is
enabled. Anonymous "not spam" is refused (spammers could whitelist
themselves).

Every accepted report (anonymous or logged in) is also logged in
`antispam_plugin_report` — verdict, account (empty = anonymous), sender,
subject, client IP, fingerprints recorded and rule changes — and listed in the
panel under *Skrzynki → Zgłoszenia z wtyczki* (`/spambox/plugin-reports`), with
30-day counters and the most reported senders. Entries older than 180 days are
purged automatically.

The on-arrival check complements, not replaces, the cron scan: it uses the same
rules (domain/e-mail white- and blacklists of the account, header heuristics,
impersonation / BEC, DNSBL, link protection, shared feed, attachment policy) and thresholds, and is logged to `antispam_spam_score_log`
with the reason `source:thunderbird_plugin`. The message is never touched on the
server — the plugin acts on the decision locally. Attachment scanning
(ClamAV / VirusTotal) is not applied to plugin checks; the plugin uploads only
the first 1 MiB of each message.

## Distribution

The `.xpi` is built on the fly by `GET /plugin/download` (public; linked from the
home page (Thunderbird section), the account form and *Configuration → Thunderbird Plugin*). The build
bakes the server URL into `config.json` and adds its origin to the manifest's host
permissions, so users only install and (optionally) log in. Set **Public URL**
in the plugin settings when antispam runs behind a TLS-terminating proxy,
otherwise the URL is taken from the request (and may come out as `http://`).

Install in Thunderbird: *Add-ons and Themes → ⚙ → Install Add-on From File…*.
Thunderbird does not require add-on signing for this. Requires the PHP `zip`
extension on the server (present in the Docker image).

## Logging in

The user enters the mailbox address of an antispam account (`antispam_account.email`)
and either:

- the **plugin password** set on the account form (*Thunderbird plugin* panel;
  stored as bcrypt in `plugin_password_hash`), or
- for IMAP accounts, the **IMAP password** stored for the account.

The server returns a stateless HMAC token (signed with `kernel.secret`), valid for
`plugin.token_ttl_days` (default 90). Deleting the account invalidates its tokens;
changing `secret` invalidates all of them. Login is limited to 10 attempts per IP
per 15 minutes.

On-arrival checks run only for messages arriving to a Thunderbird account having
an identity with the logged-in e-mail, so rules of one mailbox are never applied
to another.

## Plugin behaviour

- **Junk / not-junk in Thunderbird** → report (option *Report when I mark a message
  as junk*). Junk changes within 2 minutes of a message arriving are ignored —
  those come from Thunderbird's own classifier, not the user.
- **Toolbar button** in the message view and **context menu** in the message list:
  report spam (then mark as junk and optionally move to the Junk folder), not spam,
  check now.
- **Decision handling** (logged in): spam → mark + move to Junk (default),
  quarantine → nothing (default); both configurable.
- **Feedback**: explicit actions (toolbar button, context menu) show their result
  as a badge on the toolbar button (✓ / !, details in its tooltip) besides the
  system notification. An action that needs a login ("check", "not spam") or a
  server URL opens the plugin settings.

## Troubleshooting

The settings page header shows the server URL and whether it is reachable.
If it says *Brak połączenia z serwerem* with an `http://` URL, the `.xpi` was
built behind a TLS-terminating proxy that Symfony did not trust: set
`SYMFONY_TRUSTED_PROXIES` (or **Public URL** in the plugin settings) and
download the plugin again, or change the address in the plugin settings to
`https://…` and save (Thunderbird asks for the host permission).

## Settings (`plugin.*`, *Configuration → Thunderbird Plugin*)

| Key | Default | Meaning |
|-----|---------|---------|
| `plugin.enabled` | on | API and download available |
| `plugin.anonymous_reports` | on | Accept spam reports without login |
| `plugin.check_enabled` | on | Allow on-arrival checks |
| `plugin.learn_rules` | on | Logged-in reports create e-mail black/whitelist rules |
| `plugin.token_ttl_days` | 90 | Login token lifetime |
| `plugin.report_rate_limit` | 120 | Reports per hour per IP (anonymous) or account |
| `plugin.public_url` | (empty) | Base URL baked into the downloaded plugin |

## HTTP API (`/api/plugin`)

JSON in / JSON out, exempt from form login. Authenticated calls send
`Authorization: Bearer <token>`. Messages are sent as the base64 of the raw
RFC 822 source (`raw_base64`, max 4 MiB decoded).

| Method | URL | Auth | Description |
|--------|-----|------|-------------|
| GET | `/api/plugin/status` | optional | Feature flags, whether the token is valid |
| POST | `/api/plugin/login` | — | `{email, password}` → `{token, email, expires_at}` |
| POST | `/api/plugin/report` | optional for `spam`, required for `ham` | `{raw_base64, verdict: "spam"\|"ham"}` → `{verdict, sender, signals, rules[], authenticated}` |
| POST | `/api/plugin/check` | required | `{raw_base64}` → `{decision, spam, score, spam_threshold, quarantine_threshold, reasons[], sender, subject}` |
| GET | `/plugin/download` | — | The `.xpi` |

Errors: `400` bad payload, `401` login required / bad credentials / expired token,
`403` feature disabled, `413` message too large, `429` rate limit.

```bash
TOKEN=$(curl -s -X POST https://antispam.example.com/api/plugin/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"jan@example.pl","password":"secret"}' | jq -r .token)

curl -s -X POST https://antispam.example.com/api/plugin/check \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"raw_base64\":\"$(base64 -w0 message.eml)\"}"
```
