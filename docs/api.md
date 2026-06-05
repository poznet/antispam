# Web Endpoints

## Account Management (`/account`)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/account/index` | List all accounts |
| GET/POST | `/account/add` | Add new account form |
| GET/POST | `/account/edit/{id}` | Edit account |
| GET | `/account/del/{id}` | Delete account |
| GET | `/account/test/{id}` | Test connection (IMAP or SSH) |
| GET | `/account/deploy/{id}` | Deploy agent to hosting (SSH only) |
| GET | `/account/sync/{id}` | Sync rules to hosting (SSH only) |
| GET | `/account/scan/{id}` | Run spam scan |
| GET | `/account/download-agent` | Download agent PHP script |

## Spambox (`/spambox`)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/spambox/index` | View first 20 spam messages |

## Configuration (`/config`)

| Method | URL | Description |
|--------|-----|-------------|
| GET/POST | `/config/email/` | Legacy email account settings |
| GET/POST | `/config/spam/` | Spam processing settings |
| GET/POST | `/config/feed/` | Shared spam feed settings |
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
