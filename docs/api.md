# Web Endpoints

## Home page and login

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Public home page (product landing) with the admin login form (`#logowanie`); logged-in admins see a link to the panel |
| GET | `/login` | Redirects to `/#logowanie` (form_login entry point and failed-login redirect; the error is shown on the home page) |
| POST | `/login` | Form login check (`_username`, `_password`, CSRF token `authenticate`) → `/panel` |
| GET | `/logout` | Log out → `/` |
| GET | `/panel` | Admin dashboard |

## Account Management (`/account`)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/account/index` | List all accounts |
| GET/POST | `/account/add` | Add new account form (POST needs CSRF token `account_form`) |
| GET/POST | `/account/edit/{id}` | Edit account (POST needs CSRF token `account_form`) |
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
| GET | `/spambox/quarantine` | Quarantine of every mailbox (legacy IMAP `QUARANTINE` + each SSH account with a deployed agent) and the last 30 days of `quarantine` decisions from the score log (what the dashboard tile counts) |
| POST | `/spambox/quarantine/action` | `mailbox` (`imap` / `ssh-<id>`), `id`, `action` (`release` / `whitelist` / `delete`); CSRF token `quarantine_action` |
| GET | `/spambox/scorelog` | Last 100 score log entries with reasons |

## Configuration (`/config`)

| Method | URL | Description |
|--------|-----|-------------|
| GET/POST | `/config/email/` | Legacy email account settings |
| GET/POST | `/config/spam/` | Spam processing settings |
| GET/POST | `/config/feed/` | Shared spam feed settings |
| GET/POST | `/config/digest/` | Quarantine digest settings, mailbox list, "send now" |
| GET | `/config/digest/preview/{key}` | Render the digest a mailbox would get (last 7 days) |
| GET/POST | `/config/plugin/` | Thunderbird plugin settings |
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

## Thunderbird Plugin API (`/api/plugin`)

Used by the Thunderbird plugin. Bearer-token auth (token from `/api/plugin/login`),
exempt from form login. Full reference: **[thunderbird.md](thunderbird.md)**.

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/api/plugin/status` | Feature flags + token validity |
| POST | `/api/plugin/login` | Mailbox e-mail + plugin/IMAP password → token |
| POST | `/api/plugin/report` | User verdict (`spam` anonymous or logged in, `ham` logged in) |
| POST | `/api/plugin/check` | Score a raw message (logged in) |
| GET | `/plugin/download` | Download the `.xpi` (public) |

## Whitelists

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/whitelist/index` | Domain whitelist |
| POST | `/whitelist/add` | Add domain to whitelist |
| GET | `/whitelist/del/{id}` | Remove from whitelist |
| GET | `/emailwhitelist/index` | Email whitelist |
| POST | `/emailwhitelist/add` | Add email to whitelist |
| GET | `/emailwhitelist/del/{id}` | Remove from email whitelist |

## Blacklists

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/domainblacklst/index` | Domain blacklist |
| POST | `/domainblacklst/add` | Add domain to blacklist |
| GET | `/domainblacklst/del/{id}` | Remove from blacklist |
| GET | `/emailblacklst/index` | Email blacklist |
| POST | `/emailblacklst/add` | Add email to blacklist |
| GET | `/emailblacklst/del/{id}` | Remove from email blacklist |
