# Local learned classifier (Bayes)

An optional naive Bayes filter that learns from your users' verdicts and catches
spam the rules miss: clean SPF/DKIM/DMARC, no blacklist / DNSBL / feed hit, but
content that looks like the spam this installation has seen. Everything stays on
this server. **Off by default** - Ustawienia → Filtr spamu → *Klasyfikator
uczący się (Bayes)*.

## Why built-in and not Rspamd / SpamAssassin

A built-in classifier needs no extra service, works the same for IMAP, the
plugins and the SSH+Maildir agent (the agent gets a token table, see below) and
learns from the verdicts the panel already collects. A bridge to an external
Rspamd (`/checkv2`) or `spamd` would need its own container, its own learning
(`rspamc learn_spam` with the raw message - which the panel mostly does not have
for agent mailboxes) and would not reach the agent. It is not implemented; the
pipeline is ready for it (one more listener at a free priority) if a deployment
already runs Rspamd.

## How it scores

1. **Tokens** (`Services/Bayes/BayesTokenizer`): subject words
   (`subject:<word>`), body words (text part, else the HTML part without tags),
   link hosts (`url:<host>`, `url:<last two labels>`), From / Reply-To /
   Message-ID domains, `replyto:differs`, X-Mailer (digits collapsed),
   top-level content type. Lower-cased, Polish diacritics kept, words of 3-20
   characters (longer ones become `skip:<first letter>:<length/10*10>`), pure
   numbers dropped, each token once per message, at most 1000 per message,
   at most 100 KiB of text and HTML read.
2. **Token probability** - Robinson: `f(w) = (0.45 * 0.5 + n * p(w)) / (0.45 + n)`,
   `p(w)` from the spam / ham frequencies normalised by the number of learned
   spam / ham messages.
3. **Combining** - Fisher / Robinson chi-square (SpamBayes): the up to 150
   strongest tokens with `|f - 0.5| >= 0.1`,
   `S = 1 - chi2Q(-2 Σ ln(1-f), 2n)`, `H = 1 - chi2Q(-2 Σ ln f, 2n)`,
   `p = (S - H + 1) / 2`.
4. **Points** (configurable, `bayes.*` in the `config` table):

| Probability | Default points | Key |
|-------------|----------------|-----|
| `p >= 0.99` | **+5** (= default quarantine threshold) | `bayes.spam_score` |
| `p >= 0.90` | +3 | `bayes.likely_score` |
| `p <= 0.01` | −2 (never for a sender that hit a blacklist rule) | `bayes.ham_score` |

The reason in the score log is `bayes:<p>` (two decimals, rounded towards 0.5,
e.g. `bayes:0.99`). With the defaults Bayes alone can quarantine a message but
not send it to SPAM - like the header cap, SPAM needs a second signal.

**Minimum training:** nothing is scored until the scope has learned at least
`bayes.min_spam` spam and `bayes.min_ham` ham messages (default 50 / 50).

Where it runs: `CheckBayes` in the IMAP pipeline (priority 99972, after the
attachment checks, before `ApplyScoreDecision`), the plugin `/api/plugin/check`
scanner (`RawMessageScanner`) and the Maildir agent. It respects the global and
per-mailbox scoring switch (Konta → Ustawienia skrzynki → punktacja) and the
per-mailbox thresholds; there is no separate per-mailbox Bayes on/off.

## How it learns

Only explicit user verdicts are learned - never the filter's own decisions
(that would just reinforce its mistakes):

| Source | Verdict | Notes |
|--------|---------|-------|
| Plugin "spam" / "nie spam" (`/api/plugin/report`) | spam / ham | only reports with a logged-in mailbox; anonymous spam reports are not learned (poisoning) |
| Plugin phishing report (`/api/plugin/phishing`) | spam | |
| Quarantine *Przywróć* / *Zawsze akceptuj* (panel, `/my/quarantine`, digest `/q/` link) | ham | IMAP mailboxes: the message is read before it is moved |
| `/my/spam` *Przywróć* (IMAP) and panel *Folder spamu → Przywróć* (legacy mailbox) | ham | |
| `antispam:bayes:train` | spam / ham | bootstrap from IMAP folders |

Not learned: quarantine *Usuń* (deleting is not a reliable "this is spam" - users
delete unwanted but legitimate mail too) and releases from **SSH+Maildir**
mailboxes (the agent moves the file on the server; the panel never sees the
message). Plugin reports work for every mailbox type.

A message is identified by its Message-ID (or, without one, by its token set).
Learning it again with the same verdict does nothing; with the other verdict
(reported as spam, later released) it is **unlearned** first. Fingerprints are
kept `bayes.message_retention_days` (default 365) - after that a reversal is
learned without the unlearn step.

### Per mailbox

`bayes.per_mailbox` (*Ucz się także osobno dla każdej skrzynki*): every verdict
is learned into the global table **and** the mailbox's own table (by account
id). A mailbox whose own table reached the minimum training is scored with it,
the others with the global one. The legacy mailbox (Ustawienia → E-mail) only
has the global table.

## Privacy

Tokens are stored as the first 8 bytes of their SHA-1 (signed BIGINT), never as
words; message fingerprints are SHA-1 hashes; no subject, address or body is
written. Note that a hash of a known word can be confirmed by hashing a guess,
so the table is pseudonymous, not anonymous: anyone with database access can
test whether a given word occurred in learned mail. Nothing leaves the
installation (the shared spam feed is separate, see [feed.md](feed.md)).

## Bootstrap

```bash
# learn the newest 500 messages of SPAM as spam and of INBOX as ham
php bin/console antispam:bayes:train --account=jan@firma.pl --folder=SPAM --ham-folder=INBOX --limit=500
# legacy mailbox from Ustawienia → E-mail
php bin/console antispam:bayes:train --legacy --folder=SPAM --ham-folder=INBOX
# only one side
php bin/console antispam:bayes:train --account=3 --folder=Junk
```

Messages are only read (`BODY.PEEK`, flags unchanged), never moved; larger than
2 MiB are skipped; `--limit` is 1-5000 per folder. The command works while the
classifier is switched off, so you can train first and enable scoring
afterwards. Only IMAP accounts can be used. Make sure INBOX does not hold
unfiltered spam before learning it as ham. Each run is in the audit log
(`bayes.trained`).

## Maildir agent (SSH)

The agent does not learn. Every rules sync (`antispam:agent:sync`, Konta →
Synchronizuj, automatic syncs) sends `bayes_tokens`: the most frequent tokens of
the scope the mailbox is scored with as `[hash, probability]`, only strong ones
(`|p - 0.5| >= 0.1`), at most `bayes.agent_max_tokens` (default 20 000, max
50 000; ~30 bytes per token in the JSON, ≈600 KB at 20 000). The agent (3.2+)
stores them in its SQLite `bayes_tokens` table and scores with the same
tokenizer and combining (`bayesTokenize()`, `bayesCombine()`; `AgentParityTest`
/ `BayesAgentParityTest` keep both sides equal). Because the agent only has the
top tokens, its probability can differ slightly from the panel's for messages
made of rare tokens. Disabled or untrained in the panel = an empty list = the
agent's table is cleared. `scan --no-bayes` switches it off for one run. The
table is only refreshed by a sync, so sync after a bigger training run. Agent
body decoding does not convert legacy charsets (ISO-8859-2 bodies tokenize
differently there).

## Tuning

- Start with the defaults, train with a few hundred messages each side, watch
  the score log for `bayes:` reasons, then consider raising `bayes.spam_score`
  (e.g. 7) once false positives are rare.
- Set `bayes.ham_score` to 0 if you never want Bayes to lower a score.
- Keep spam and ham roughly balanced; a very lopsided corpus pushes everything
  towards the bigger class.
- **Wyczyść bazę Bayesa** (Konserwacja on the same page) deletes every token and
  fingerprint of all mailboxes (audit: `bayes.reset`).

## Storage and housekeeping

| Table | Columns | Purpose |
|-------|---------|---------|
| `antispam_bayes_token` | `id`, `scope` (0 = global / account id), `token_hash` BIGINT, `spam_count`, `ham_count`, `updated_at`; unique (`scope`, `token_hash`), index `updated_at` | token counts; the row `token_hash = 0` of a scope holds the learned message totals |
| `antispam_bayes_message` | `id`, `scope`, `fingerprint` CHAR-40, `verdict` (spam/ham), `source`, `learned_at`; unique (`scope`, `fingerprint`), index `learned_at` | learned messages (dedupe / unlearn) |

Writes are batched upserts (MySQL/MariaDB `INSERT ... ON DUPLICATE KEY UPDATE`;
`ON CONFLICT` on SQLite in the tests), counts change in SQL so parallel training
loses nothing.

`antispam:purge` (daily): fingerprints older than `bayes.message_retention_days`
(365), tokens seen in a single message and untouched for
`bayes.token_retention_days` (180, the bulk of the table), rows of deleted
accounts. Message totals are kept. `antispam:doctor` check `bayes` reports the
counts (WARN while enabled but under the minimum training).

**Backups** (`antispam:export`, Ustawienia → Kopia zapasowa) do **not** include
the token tables - they are derived data and can be large. The `bayes.*`
settings are in the `config` section and are restored. After moving to a new
server either retrain or copy the two tables with `mysqldump`.
