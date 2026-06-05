# Shared Spam Feed — HTTP API Reference

Machine-to-machine API behind the [shared spam feed](feed.md) (the centralized
spam DB). Instances use it to **report** spam fingerprints to a hub and **pull**
fingerprints reported by others. This document is the complete contract for the
endpoints; for the concepts (what a fingerprint is, why, how it scores) see
[feed.md](feed.md).

All routes are served by `SpamFeedApiController` and mounted under `/api/feed`.

---

## Base URL

```
https://<your-host>/api/feed
```

The hub URL configured on a client (`feed.remote_url`) is the **base host only**
— the client appends `/api/feed/...` itself.

## Authentication

Every request must carry the shared secret in the `X-Feed-Key` header:

```
X-Feed-Key: <feed.server_key of the receiving instance>
```

The key is compared against the receiving instance's `feed.server_key` config
value (Settings → Shared Spam Feed) using a constant-time comparison.

| Condition                                   | Status | Body |
|---------------------------------------------|--------|------|
| `feed.server_key` is empty (API disabled)   | `403`  | `{"error":"feed api disabled"}` |
| Header missing or does not match the key    | `401`  | `{"error":"unauthorized"}` |
| Key matches                                 | —      | request is processed |

> The disabled check happens first: if no server key is configured the API
> rejects everything with `403`, regardless of what header is sent.

## Conventions

- **Request bodies** (POST): JSON, `Content-Type: application/json`.
- **Responses**: always JSON.
- **Timestamps**: ISO 8601 / RFC 3339 (`DateTime::ATOM`), e.g.
  `2026-06-05T12:30:00+00:00`.
- There is **no API version prefix** — the surface is small and additive.

## The signal object

A signal is a single spam fingerprint:

```json
{ "type": "sender", "hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }
```

| Field  | Type   | Rules |
|--------|--------|-------|
| `type` | string | `"sender"` or `"body"` (anything else is rejected) |
| `hash` | string | lower-case hex **SHA-256**, exactly 64 chars matching `^[a-f0-9]{64}$` |

How the hashes are computed is documented in [feed.md](feed.md#what-is-shared-and-what-is-not).
The API never sees or stores raw addresses or message bodies.

---

## Endpoints

### POST `/api/feed/report`

Submit a batch of spam fingerprints. Existing signals have their `reports`
counter incremented; new ones are created with `origin = remote`.

**Request body**

```json
{
  "signals": [
    { "type": "sender", "hash": "<64-hex sha256>" },
    { "type": "body",   "hash": "<64-hex sha256>" }
  ]
}
```

**Validation**

- The body must be a JSON object containing a `signals` array, otherwise `400`.
- Each array item is validated individually. Items with an invalid `type` or a
  `hash` that is not 64-char lower-case hex are **silently skipped** — they do
  not cause an error, they just are not counted in `accepted`.

**Response** `200 OK`

```json
{ "accepted": 2, "received": 2 }
```

| Field      | Meaning |
|------------|---------|
| `received` | number of items in the submitted `signals` array |
| `accepted` | number of valid items that were stored/updated |

`accepted < received` means some items were dropped as invalid.

**Errors**

| Status | Body | Cause |
|--------|------|-------|
| `400`  | `{"error":"invalid payload"}` | body is not an object, or `signals` is missing / not an array |
| `401` / `403` | see [Authentication](#authentication) | auth failure |

**Example**

```bash
curl -sS -X POST https://hub.example.com/api/feed/report \
  -H "X-Feed-Key: $FEED_KEY" \
  -H "Content-Type: application/json" \
  -d '{"signals":[
        {"type":"sender","hash":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
        {"type":"body","hash":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"}
      ]}'
# {"accepted":2,"received":2}
```

---

### GET `/api/feed/pull`

Return signals **updated after** a given timestamp, for incremental sync. The
response includes a `now` timestamp the caller should store and pass as `since`
on the next call so each pull only transfers the delta.

**Query parameters**

| Param   | Required | Default | Notes |
|---------|----------|---------|-------|
| `since` | no       | —       | ISO 8601 timestamp; only signals with `updated_at > since` are returned. Omit on the first call to get everything (up to `limit`). |
| `limit` | no       | `5000`  | Clamped to the range `1..5000`. |

Signals are ordered by `updated_at` ascending (then `id`), so paging by
advancing `since` is stable.

**Response** `200 OK`

```json
{
  "signals": [
    {
      "type": "sender",
      "hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "reports": 7,
      "updated_at": "2026-06-05T12:29:58+00:00"
    }
  ],
  "count": 1,
  "now": "2026-06-05T12:30:00+00:00"
}
```

| Field     | Meaning |
|-----------|---------|
| `signals` | array of signal objects (with `reports` and `updated_at`) |
| `count`   | number of signals returned (== `signals.length`) |
| `now`     | server time at the moment of the response — store this as the next `since` |

If `count` equals `limit`, more rows may be waiting: call again with `since` set
to the last `updated_at` (or to `now`) to continue.

**Errors**

| Status | Body | Cause |
|--------|------|-------|
| `400`  | `{"error":"invalid since"}` | `since` is present but not a parseable timestamp |
| `401` / `403` | see [Authentication](#authentication) | auth failure |

**Example**

```bash
# First pull — everything (capped at limit)
curl -sS "https://hub.example.com/api/feed/pull" -H "X-Feed-Key: $FEED_KEY"

# Incremental pull — only what changed since the last 'now'
curl -sS "https://hub.example.com/api/feed/pull?since=2026-06-05T12:30:00%2B00:00&limit=2000" \
  -H "X-Feed-Key: $FEED_KEY"
```

> `+` must be URL-encoded as `%2B` inside the query string.

---

### GET `/api/feed/stats`

Lightweight health/identity check — also the cheapest way to confirm a key
works. Returns signal counts by origin.

**Response** `200 OK`

```json
{ "signals": { "local": 1280, "remote": 9043, "total": 10323 } }
```

| Field    | Meaning |
|----------|---------|
| `local`  | signals this instance detected itself |
| `remote` | signals pulled from other instances |
| `total`  | sum of the two |

**Errors:** `401` / `403` on auth failure (see [Authentication](#authentication)).

**Example**

```bash
curl -sS https://hub.example.com/api/feed/stats -H "X-Feed-Key: $FEED_KEY"
# {"signals":{"local":1280,"remote":9043,"total":10323}}
```

---

## Status codes at a glance

| Code | When |
|------|------|
| `200` | request processed |
| `400` | malformed request (bad JSON body / missing `signals` / unparseable `since`) |
| `401` | `X-Feed-Key` missing or wrong |
| `403` | API disabled on this instance (`feed.server_key` empty) |

## Semantics & guarantees

- **Upsert / idempotent-ish.** Re-reporting the same `{type, hash}` does not
  duplicate it; it increments the signal's `reports` counter and refreshes
  `updated_at`. Reporting is therefore safe to retry, but each accepted call
  bumps the counter (it is not strictly idempotent on the count).
- **Invalid items are tolerated.** A batch with some bad items still succeeds;
  the bad items are dropped and reflected in `accepted` vs `received`.
- **Batch size.** `pull` returns at most 5000 signals per call. There is no hard
  server limit on `report` batch size, but keep batches reasonable (the built-in
  client uses 1000) to stay within PHP request limits.
- **Privacy.** Only SHA-256 hashes cross the wire. The server cannot recover the
  original sender or body from a hash.

## Reference client

The bundled `antispam:feed:sync` command (see [commands.md](commands.md) and
[feed.md](feed.md#syncing)) implements the full client flow:

1. **Push:** `POST /api/feed/report` for local signals newer than the stored
   `feed.last_push_id`, in batches of 1000, advancing the checkpoint.
2. **Pull:** `GET /api/feed/pull?since=<feed.last_pull_at>`, import the returned
   signals as `origin = remote`, then store the response `now` as the new
   `feed.last_pull_at`.

A minimal equivalent in shell:

```bash
HUB=https://hub.example.com
KEY=$FEED_KEY

# push one signal
curl -sS -X POST "$HUB/api/feed/report" -H "X-Feed-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"signals":[{"type":"sender","hash":"<64-hex>"}]}'

# pull and save the cursor
resp=$(curl -sS "$HUB/api/feed/pull?since=$SINCE" -H "X-Feed-Key: $KEY")
echo "$resp" | jq '.signals'
echo "$resp" | jq -r '.now'   # persist as the next ?since
```
