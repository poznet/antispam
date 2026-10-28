# Web Endpoints

## Home page and login

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Public home page (product landing) with the admin login form (`#logowanie`); logged-in admins see a link to the panel |
| GET | `/login` | Redirects to `/#logowanie` (form_login entry point and failed-login redirect; the error is shown on the home page) |
| POST | `/login` | Form login check (`_username`, `_password`, CSRF token `authenticate`) → `/panel` |
| GET | `/logout` | Log out → `/` |
| GET | `/start` | After-login redirect (ROLE_USER): admins -> `/panel`, users -> `/my/quarantine` |
| GET | `/panel` | Admin dashboard (ROLE_ADMIN) |

Access: `/`, `/login`, `/api/feed`, `/q/`, `/api/plugin` and the plugin downloads are public;
`/my/*` and `/start` need `ROLE_USER` (admins included); **everything else needs `ROLE_ADMIN`**.
See [users.md](users.md).

## My mailbox (`/my`, ROLE_USER)

Every action is limited to the mailboxes assigned to the user (an administrator sees all);
a foreign mailbox key gives 403, see [users.md](users.md).

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/my/quarantine` | Quarantine of the user's mailboxes (IMAP / SSH accounts only; not the legacy mailbox) |
| POST | `/my/quarantine/action` | `mailbox` (`imap-<id>` / `ssh-<id>`, must be assigned), `id`, `action` (`release` / `whitelist` / `delete`); CSRF token `my_quarantine_action`. `whitelist` is refused for high-risk messages |
| GET | `/my/scorelog` | Own score log (same template and filters as `/spambox/scorelog`; `account` is limited to the user's mailboxes). `?decision=spam` is the user's "spam" view |
| GET/POST | `/my/password` | Change own password (database users only; CSRF token `my_password`); logs out afterwards |

## Users (`/users`, ROLE_ADMIN)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/users` | List users |
| GET/POST | `/users/add` | Create a user: login, password, role, mailboxes (CSRF token `user_form`) |
| GET/POST | `/users/edit/{id}` | Edit; empty password keeps the current one (CSRF token `user_form`) |
| POST | `/users/del/{id}` | Delete (CSRF token `user_action_{id}`); not your own account |

## Account Management (`/account`)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/account/index` | List all accounts |
| GET/POST | `/account/add` | Add new account form (POST needs CSRF token `account_form`) |
| GET/POST | `/account/edit/{id}` | Edit account (POST needs CSRF token `account_form`) |
| POST | `/account/imap-check` | IMAP connection / TLS certificate check from the account form, JSON; `mode=detect` suggests SSL/TLS or STARTTLS (CSRF token `imap_check`) |
| POST | `/account/del/{id}` | Delete account (CSRF token `account_action_{id}`) |
| POST | `/account/test/{id}` | Test connection (IMAP or SSH) (CSRF token `account_action_{id}`) |
| POST | `/account/deploy/{id}` | Deploy agent to hosting (SSH only) (CSRF token `account_action_{id}`) |
| POST | `/account/sync/{id}` | Sync rules to hosting (SSH only) (CSRF token `account_action_{id}`) |
| POST | `/account/scan/{id}` | Run spam scan (CSRF token `account_action_{id}`) |
| POST | `/account/health/{id}` | Agent health check (SSH only, CSRF token `account_action_{id}`) |
| GET | `/account/download-agent` | Download agent PHP script |

## Spambox (`/spambox`)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/spambox/index` | View first 20 spam messages |
| GET | `/spambox/quarantine` | Quarantine of every mailbox (legacy IMAP `QUARANTINE`, each IMAP account, each SSH account with a deployed agent) and the last 30 days of `quarantine` decisions from the score log (what the dashboard tile counts) |
| POST | `/spambox/quarantine/action` | `mailbox` (`imap` / `imap-<id>` / `ssh-<id>`), `id`, `action` (`release` / `whitelist` / `delete`); CSRF token `quarantine_action` |
| GET | `/spambox/scorelog` | Score log ("Dziennik ocen"), 50 per page. Query filters: `decision` (`ham`/`quarantine`/`spam`/`whitelisted`), `account`, `q` (sender/subject substring), `from`/`to` (`Y-m-d`), `min_score`, `page`. The decision tiles link to the matching `decision` filter |
| GET | `/spambox/plugin-reports` | Mail plugin reports - Thunderbird and Outlook (anonymous + logged in), filters `?verdict=spam\|ham`, `?who=anonymous\|account` |

## Phishing reports (`/phishing`)

See [phishing.md](phishing.md). CSRF token id `phishing` for all POSTs.

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/phishing/` | List, filters `?status=new\|confirmed\|reported\|false_positive`, `?account=`, `?q=`, `?page=` |
| GET | `/phishing/{id}` | Analysis: headers, auth results, red flags, links, attachments, body |
| POST | `/phishing/{id}/update` | `status`, `note` |
| POST | `/phishing/{id}/block` | `what=sender\|domain` - blacklist rule for the reporting mailbox + retroactive pass |
| GET | `/phishing/{id}/eml` | Original message as `.eml` download |
| POST | `/phishing/{id}/delete` | Delete the report and its content |

## Cron log (`/cron`)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/cron/logs` | Runs recorded by `antispam:cron:run` (last 200), filters `?command=…`, `?failed=1`. See [spam-handling.md](spam-handling.md) |

## CERT list (`/cert`)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/cert/` | Status, settings form, domain lookup `?q=domain-or-url` (subdomains of listed domains match), paginated view `?page=N` |
| POST | `/cert/` | Save enabled/score (CSRF token `cert_config`) |
| POST | `/cert/sync` | Download the list now (CSRF token `cert_config`) |

## Configuration (`/config`)

| Method | URL | Description |
|--------|-----|-------------|
| GET/POST | `/config/email/` | Legacy email account settings, same SSL/TLS options as the account form (POST needs CSRF token `email_config`) |
| GET/POST | `/config/spam/` | Spam processing settings |
| GET/POST | `/config/feed/` | Shared spam feed settings |
| GET/POST | `/config/digest/` | Quarantine digest settings, mailbox list, "send now" |
| GET | `/config/digest/preview/{key}` | Render the digest a mailbox would get (last 7 days) |
| GET/POST | `/config/plugin/` | Mail client plugin settings + downloads (Thunderbird, Outlook, Apple Mail) |
| GET | `/config/uncheck-all/` | Reset all checked messages |
| GET | `/config/reset/countes/` | Reset all rule counters |

## Shared Spam Feed API (`/api/feed`)

Machine-to-machine endpoints for the centralized spam DB. Authenticated with the
`X-Feed-Key` header (matched against `feed.server_key`), exempt from form login.
JSON in / JSON out. Full reference with request/response schemas, error codes and
examples: **[feed-api.md](feed-api.md)** (concepts: [feed.md](feed.md)).

| Method | URL | Description |
|--------|-----|-------------|
| POST | `/api/feed/report` | Accept a batch of `{type, hash}` spam fingerprints |
| GET | `/api/feed/pull` | Return signals updated since `?since=<ISO8601>` (incremental) |
| GET | `/api/feed/stats` | Signal counts by origin (local/remote/total) |

## Quarantine digest links (`/q`, public)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/q/{token}` | Confirmation page for a digest action (no side effects) |
| POST | `/q/{token}` | Perform the action (deliver / deliver + whitelist / delete) |

No login. The signed, expiring token is the credential. Invalid or expired tokens
get `410`, a failed action `409`. See [quarantine-digest.md](quarantine-digest.md).

## Mail Client Plugin API (`/api/plugin`)

Used by the Thunderbird plugin, the Outlook add-in and the Apple Mail extension.
Bearer-token auth (token from `/api/plugin/login`), exempt from form login.
Full reference: **[thunderbird.md](thunderbird.md)**, clients:
[outlook.md](outlook.md), [apple-mail.md](apple-mail.md).

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/plugin/status` | Feature flags, `max_upload_bytes` + token validity (`authenticated`, always 200) |
| POST | `/api/plugin/login` | Mailbox e-mail + plugin/IMAP password → token |
| POST | `/api/plugin/report` | User verdict (`spam` anonymous or logged in, `ham` logged in) |
| POST | `/api/plugin/check` | Score a raw message (logged in) |
| POST | `/api/plugin/phishing` | Phishing report: full message stored for the admin + spam report (logged in) |
| GET | `/plugin/download` | Download the `.xpi` (public, `Cache-Control: private, no-store`) |
| GET | `/plugin/outlook/manifest.xml` | Outlook add-in manifest (public; `409` when the server URL is not HTTPS) |
| GET | `/plugin/outlook/{file}` | Outlook task pane files (`taskpane.html/js/css`, `commands.html`, `icons/icon-*.png`; public) |
| GET | `/plugin/apple-mail/source.zip` | Apple Mail extension source with the server URL set (public) |

## Whitelists

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/whitelist/index` | Domain whitelist; `?owner=<mailbox>` filters by owner (`*` = global rules only) |
| POST | `/whitelist/add` | Add domain to whitelist: `host`, `pattern_type`, `owner` (mailbox from the selector or `*`, see [Rule ownership](scoring.md#rule-ownership)); CSRF token `list_rules` |
| POST | `/whitelist/del/{id}` | Remove from whitelist (CSRF token `list_rules`) |
| GET | `/emailwhitelist/index` | Email whitelist; `?owner=` filter as above |
| POST | `/emailwhitelist/add` | Add email to whitelist: `email`, `pattern_type`, `owner`; CSRF token `list_rules` |
| POST | `/emailwhitelist/del/{id}` | Remove from email whitelist (CSRF token `list_rules`) |

## Blacklists

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/domainblacklst/index` | Domain blacklist; `?owner=` filter as above |
| POST | `/domainblacklst/add` | Add domain to blacklist: `host`, `pattern_type`, `score`, `owner`; CSRF token `list_rules`; matching INBOX mail from the last 30 days is moved to SPAM ([spam-handling.md](spam-handling.md#retroactive-blacklist)) |
| POST | `/domainblacklst/del/{id}` | Remove from blacklist (CSRF token `list_rules`) |
| GET | `/emailblacklst/index` | Email blacklist; `?owner=` filter as above |
| POST | `/emailblacklst/add` | Add email to blacklist: `email`, `pattern_type`, `score`, `owner`; CSRF token `list_rules`; matching INBOX mail is moved to SPAM, as above |
| POST | `/emailblacklst/del/{id}` | Remove from email blacklist (CSRF token `list_rules`) |

## Bulk import / export

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/bulk/` | Import / export page for the four rule lists |
| POST | `/bulk/import/{type}` | `type` = `blacklist`, `whitelist`, `email_blacklist`, `email_whitelist`; `entries` (one rule per line, `#` comments; `,`/`;` separate exact and wildcard entries, regex lines are kept verbatim), `pattern_type`, `score` (blacklists), `owner` (mailbox or `*`); CSRF token `bulk_import` (403 without it). Lines in the export format (`value<TAB>pattern_type[<TAB>score][<TAB>owner]`) are accepted: their pattern type / score override the form, the owner column is ignored. Duplicates are skipped per owner ([Rule ownership](scoring.md#rule-ownership)). No retroactive pass |
| GET | `/bulk/export/{type}` | Plain-text export, tab-separated `value, pattern_type[, score], owner`; `?owner=<mailbox or *>` exports one owner only |
