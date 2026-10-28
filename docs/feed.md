# Shared Spam Feed (centralized spam DB)

The shared spam feed lets multiple antispam instances pool what they catch.
When one instance decides a message is spam it records a small, privacy-safe
fingerprint of it; that fingerprint can be pushed to a central hub and pulled by
other instances, which then score incoming mail against it. So spam confirmed on
one instance is caught faster everywhere else.

Every instance can be **both a hub and a client** at the same time — it is just
a matter of which config fields you fill in.

## What is shared (and what is not)

Only **one-way SHA-256 hashes** ever leave an instance. Raw addresses and
message bodies are never transmitted or stored centrally. Two signals are
produced per spam message:

| Signal   | How it is built                                                                 | Why |
|----------|---------------------------------------------------------------------------------|-----|
| `sender` | normalized From address (lower-cased, plus-addressing stripped) → SHA-256       | spammers reuse from-addresses across many recipients — high hit rate |
| `body`   | body with the **last 3 lines (signature) removed**, lower-cased, URLs/e-mails/digits stripped, whitespace collapsed → SHA-256 | collapses a whole campaign to one hash even when each copy is personalized |

### Why not just MD5 the whole message?

A hash of the raw message is cheap to compute and tiny to send, so volume is
**not** the concern — but its hit rate is terrible. Spam is personalized
(recipient name, unique unsubscribe links, tracking pixels, differing
`Received`/`Date` headers), so the same campaign produces a different hash for
every recipient and almost never matches across instances. Normalizing the body
(and dropping the signature) before hashing is what makes the `body` signal
actually match across mailboxes. SHA-256 is used instead of MD5 to avoid
collisions.

## Storage

Signals live in `antispam_shared_spam_signal`:

| Column       | Notes                                                        |
|--------------|--------------------------------------------------------------|
| `type`       | `sender` or `body`                                           |
| `hash`       | lower-case hex SHA-256 (unique together with `type`)         |
| `origin`     | `local` (detected here, eligible to push) or `remote` (pulled) |
| `reports`    | how many observations have accumulated (corroboration)       |
| `created_at` / `updated_at` | `updated_at` drives incremental pulls         |

The table is part of the baseline migration; `antispam:db:upgrade` creates it
(the Docker entrypoint runs it at boot):

```bash
php bin/console antispam:db:upgrade
```

## Configuration

**Ustawienia → Wspólna baza spamu** (`feed.*` config keys):

| Field             | Key                | Meaning |
|-------------------|--------------------|---------|
| Participate       | `feed.enabled`     | record fingerprints + score incoming mail against the feed |
| Match score       | `feed.score`       | points added when incoming mail matches a trusted signal (default 6) |
| Minimum reports   | `feed.min_reports` | a signal is trusted only after this many observations (default 1) |
| Local API key     | `feed.server_key`  | secret other instances present to push/pull here; empty disables the API |
| Remote hub URL    | `feed.remote_url`  | base URL this instance syncs against, `https://` only (empty or non-https → hub-only) |
| Remote key        | `feed.remote_key`  | secret presented to the remote hub |

## Scoring

`CheckSharedFeed` runs in the message pipeline (priority `99978`, just after
DNSBL). It hashes the incoming message's sender and body, looks them up, and —
for each signal seen at least `feed.min_reports` times — adds `feed.score` and a
`shared_feed:<type>` reason to the score log.

`RecordSpamSignals` runs after the final decision (priority `99965`, before the
message is moved/deleted). When the message was judged spam it stores the local
fingerprints (`origin = local`).

## Syncing

`antispam:feed:sync` is the client side. It pushes local signals the hub has not
seen yet and pulls signals updated since the last run:

```bash
php bin/console antispam:feed:sync             # push then pull
php bin/console antispam:feed:sync --push-only
php bin/console antispam:feed:sync --pull-only
```

Run it from cron (e.g. every 15 minutes). Push/pull checkpoints are stored in
`feed.last_push_id` and `feed.last_pull_at`, so each run only transfers the
delta. Push batches are capped at the hub's limit of 1000 signals (`--batch`
above that is lowered, it would only get `413`). Pull pages through the hub
with a `(updated_at, id)` cursor until a page comes back short (max 200 pages
of 5000 per run), and `feed.last_pull_at` is the hub time of the last row
received - see [feed-api.md](feed-api.md#reference-client).

Pulled signals keep `reports = max(local, hub)` rather than adding one per pull:
the hub's count already includes this instance's own push, so an echo of your
own signal never satisfies `feed.min_reports` on its own. A local signal stays
`origin = local`.

## HTTP API (hub side)

> Full request/response contract, error codes and examples:
> **[feed-api.md](feed-api.md)**.

All routes are under `/api/feed` and require the `X-Feed-Key` header to match
`feed.server_key`. They are exempt from the form-login firewall in
`config/packages/security.yaml`. Responses are JSON.

| Method | Path               | Body / query                              | Returns |
|--------|--------------------|-------------------------------------------|---------|
| POST   | `/api/feed/report` | `{"signals":[{"type","hash"}, ...]}`      | `{accepted, received}` |
| GET    | `/api/feed/pull`   | `?since=<ISO8601>&after_id=<id>&limit=<n>` (all optional) | `{signals:[{id,type,hash,reports,updated_at}], count, limit, has_more, next, now}` |
| GET    | `/api/feed/stats`  | —                                         | `{signals:{local,remote,total}}` |

Example push:

```bash
curl -X POST https://hub.example.com/api/feed/report \
  -H "X-Feed-Key: <server key>" -H "Content-Type: application/json" \
  -d '{"signals":[{"type":"sender","hash":"<64-hex>"}]}'
```

Auth failures return `401`; when `feed.server_key` is empty the API is disabled
and returns `403`.
