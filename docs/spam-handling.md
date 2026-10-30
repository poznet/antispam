# What happens to spam

How detected mail leaves INBOX, how the quarantine works, how a new blacklist
rule is applied to mail that already arrived, how a whole mailbox is checked
again with the current rules, and where to see what the periodic jobs did.

## Spam: move or delete

Every mailbox ends a scan with one of three decisions per new message
(see [scoring.md](scoring.md)):

| Decision | Score | What happens |
|----------|-------|--------------|
| ham | below the quarantine threshold | stays in INBOX |
| quarantine | quarantine threshold ≤ score < spam threshold | moved to `QUARANTINE` |
| spam | ≥ spam threshold (or a hard hit: any domain / e-mail blacklist rule, ClamAV/VirusTotal) | moved to `SPAM`, or deleted |

Spam is **moved to the `SPAM` folder** of the same mailbox by default. It is
deleted only when deletion is switched on:

| Mailbox | Setting |
|---------|---------|
| IMAP account (Konta) | *Usuwaj spam (zamiast przenosić do folderu SPAM)* on the account form (`delete_spam`) |
| Legacy mailbox (Ustawienia → Konfiguracja (stara)) | *Usuwaj spam na stałe* in Ustawienia → Filtr spamu (config `delete`) |
| SSH+Maildir account | always moved to `~/Maildir/.SPAM` (the agent never deletes spam) |

The thresholds deciding ham / quarantine / spam can differ per mailbox
(**Ustawienia skrzynki** on the account form, empty = global value); the
delete switch above has always been per account and does not inherit the
global `delete` setting, which belongs to the legacy mailbox only.

The `SPAM` and `QUARANTINE` folders are created on first use. In IMAP the
message is moved with `MOVE`/`COPY`+`\Deleted` and the INBOX is expunged at the
end of the scan. If the move fails (quota, permissions...) the score log gets
`move_failed`, the message stays in INBOX and is **retried on the next scan**
(both for SPAM and QUARANTINE; the IMAP cursor stays below it, see
[architecture.md](architecture.md#incremental-inbox-scan)).

`MoveToSpam` and `ApplyScoreDecision` act on the IMAP connection the message
came from (`MessageEvent::getConnection()`), so every IMAP account uses its own
folders. `ImapScanService` runs the pipeline for both IMAP accounts and the
legacy mailbox.

## Quarantine

Quarantine is **not deletion**: the message is moved out of INBOX into the
`QUARANTINE` folder (`~/Maildir/.QUARANTINE` for SSH accounts) and stays there
until someone acts on it. Nothing removes quarantined mail automatically.

Every quarantined message can be released:

- in the panel: **Skrzynki → Kwarantanna** - *Przywróć* (back to INBOX),
  *Zawsze akceptuj* (back to INBOX + sender on the e-mail whitelist, hidden for
  high-risk messages), **Do czarnej listy** ([below](#blacklisting-a-sender-from-the-quarantine)),
  *Usuń* (permanent); per mailbox also the bulk *Usuń od tylu punktów* /
  *Usuń wszystkie wysokiego ryzyka* / *Usuń wszystko z kwarantanny*
  ([below](#bulk-deletion));
- from the [quarantine digest](quarantine-digest.md) e-mail (signed one-click
  links, same three actions).

A released message is marked as checked, so the next scan does not quarantine
it again. The page covers the legacy mailbox (`imap`), every IMAP account
(`imap-<id>`) and every SSH account with a deployed agent (`ssh-<id>`).

### Blacklisting a sender from the quarantine

**Do czarnej listy** next to a quarantined message (admin **Skrzynki →
Kwarantanna** and `/my/quarantine`, own mailboxes only; not in digest links):

1. every message of **that sender** (exact `From` address) in the quarantine of
   **this mailbox** goes to **SPAM** - moved, never deleted. IMAP: `SEARCH FROM`
   in the quarantine folder, each hit compared with the exact address; SSH: agent
   **3.6** `quarantine-to-spam --id=...` ([agent.md](agent.md#quarantine-management));
2. the sender gets an **exact e-mail blacklist rule** owned by this mailbox
   (score 10; a blacklist hit is always spam). An existing rule for the mailbox
   or for all mailboxes is not duplicated (*reguła już istniała*);
3. a new rule queues its usual retroactive pass (`rule.retroactive`): INBOX mail
   of the last 30 days from the sender goes to SPAM too, and an SSH agent gets
   the rule synced.

Audit: `quarantine.blacklist` (`moved_to_spam`, `rule_added`) and, for a new
rule, `rule.add` with `source: quarantine`.

### Bulk deletion

Under the list of each mailbox (admin **Skrzynki → Kwarantanna** and the user's
own mailbox on `/my/quarantine`) there are three buttons, all **permanent
deletion** (`trwale`, nothing goes back to INBOX or to SPAM):

| Button | Deletes |
|--------|---------|
| **wynik od [N] pkt → Usuń od tylu punktów** (2.1.0) | the quarantined messages whose score (score log, judged when the job runs) is at least N (1-1000); a message without a known score is kept |
| **Usuń wszystkie wysokiego ryzyka** (only shown when the list has high-risk messages) | the quarantined messages that are high risk |
| **Usuń wszystko z kwarantanny** | every quarantined message of that mailbox |

The admin page also has **Usuń wszystkie wysokiego ryzyka (wszystkie skrzynki)**
above the mailboxes (when there are 2+ mailboxes and some high-risk messages):
one job per mailbox, then the job list filtered to `quarantine.purge`.

- **High risk** = a real high-risk reason, the same pattern that hides *Zawsze
  akceptuj* (`QuarantineDigestService::HIGH_RISK_PATTERN`): a reason
  `impersonation_*`, `lookalike_domain`, `internal_domain_spoof`,
  `display_name_embedded_address`, `attachment_*`, `clamav*`, `virustotal*`,
  `url_safebrowsing*`, `url_dbl*`, `cert_hole*`
  (`QuarantineDigestService::isPurgeableHighRisk()`). A message **without a
  score log row** (`score_unknown`) is **kept**: it still carries the *wysokie
  ryzyko* label and has no *Zawsze akceptuj* (that check fails closed), but
  permanent deletion does not - otherwise a mailbox with score logging off
  (`scoring.log_enabled`) or with rows removed by `antispam:purge` would lose its
  whole quarantine. Such messages are counted as skipped and are removed only by
  *Usuń wszystko z kwarantanny*. The SSH agent uses the same pattern
  (`AGENT_HIGH_RISK_PATTERN`, kept equal by `AgentParityTest`) on its own
  `score_log`; no row = kept there too.
- **Background job** `quarantine.purge` ([jobs.md](jobs.md)), payload mailbox
  key + mode `high_risk` / `all` / `min_score` (+ `min_score` = N); one per mailbox and mode while queued /
  running (dedupe key `quarantine.purge:<key>:<mode>`). The button redirects to
  the job page (admin `/jobs/{id}`, user `/my/jobs/{id}`) with the counts:
  messages in the quarantine, deleted, skipped (not high risk / unreadable /
  already gone), errors.
- **Decided at run time.** The confirmation (`data-confirm`) names the mailbox
  and the count on the page, but that count is only displayed and audited
  (`shown`). The job lists the quarantine folder when it runs and re-evaluates
  each message then; mail released or deleted in between is not touched, mail
  quarantined in between is included. IMAP: `QuarantineService::purge()` opens
  only the quarantine folder (refuses if it were ever named `INBOX` or the SPAM
  folder), flags `\Deleted` and expunges every 100 messages. SSH: agent **3.4**
  command `quarantine-purge --mode=...` (`min_score` needs agent **3.6**,
  `--min-score=N`) ([agent.md](agent.md#quarantine-management)),
  which only unlinks files in `.QUARANTINE/new|cur`; an older agent fails the
  job with "wdróż go ponownie".
- **Permissions:** admin - any mailbox (including the legacy `imap`); ROLE_USER -
  only an assigned mailbox (`MailboxAccess`, foreign key = 403), checked again
  when the job runs (access removed meanwhile = the job fails, nothing deleted).
  CSRF tokens `quarantine_purge` / `my_quarantine_purge`. Audit:
  `quarantine.purge_queued` and `quarantine.purge` ([audit.md](audit.md)).
- Digest links (`/q/`) have no bulk action.

### Quarantine log vs. quarantine folder

The bottom table on **Kwarantanna** ("Decyzje „kwarantanna”") is the score
log (`antispam_spam_score_log`), not the folder: an entry stays after the
message was released or deleted, and plugin checks are logged without moving
anything. Each entry records:

- `source` - `scan` (server scan), `plugin` (Thunderbird/Outlook check, never
  moves mail on the server), `retro` (retroactive blacklist pass);
- `outcome` - `none`, `quarantined`, `spam_folder`, `deleted`, `move_failed`
  (decision made but the move failed, the message is still in INBOX).

The **Gdzie teraz** column combines that with the live folder listing
(`SpamboxController::locateLogs`, matched by account + sender + subject):
*w kwarantannie*, *już nie w kwarantannie* (released/deleted), *przeniesienie
nie powiodło się*, *ocena wtyczki*. Entries written before these columns
existed have both empty; old plugin entries are still recognised by their
`source:thunderbird_plugin` reason. SSH agents keep their decisions in the
agent's SQLite DB, so they never appear in this table - only in the mailbox
panels above it.

Spam in the legacy mailbox's `SPAM` folder can be restored to INBOX on
**Skrzynki → Folder spamu**. For IMAP/SSH accounts use the mail client
(the folder is a normal IMAP folder).

## Retroactive blacklist

A new blacklist rule also applies to mail that is **already in INBOX**. When a
rule is added:

- on **Blacklista domen** / **Blacklista e-mail** in the panel,
- when an existing mailbox rule is changed to **Wszystkie skrzynki** there
  (the pass then covers every mailbox; [scoring.md](scoring.md#making-a-rule-global)), or
- by a logged-in Thunderbird plugin user reporting spam (which adds an exact
  e-mail blacklist rule, see [thunderbird.md](thunderbird.md)),

`RetroactiveSpamService::applyRule()` moves matching INBOX messages from the
last 30 days (every rule type) to `SPAM` in every mailbox owned by the rule's account e-mail (a
global rule - owner **Wszystkie skrzynki**, `*` - goes through every account
and the legacy mailbox, one after another; see
[scoring.md](scoring.md#rule-ownership)). The pass is a **background job**
(`rule.retroactive`, queued by `DeferredRetroactivePass`, one pending pass per
rule, see [jobs.md](jobs.md)): the rule form answers at once with "Poczta, która
już jest w skrzynce, zostanie sprawdzona ... w tle - zadanie #N" and the job page
(**Przegląd → Zadania w tle**) shows how many were moved, skipped mailboxes and
errors. The same job runs for **Phishing → Zablokuj** and for a plugin report;
there the API only answers `"retroactive": "scheduled"` and the result goes to
the job, the application log and the score log. (Up to 2.0.0 the plugin pass
ran on `kernel.terminate` after the response and the panel pass inside the
request.)

Rules and limits:

- Mail is always **moved**, never deleted, even when deletion is on - a mistake
  can be undone from the SPAM folder.
- Senders on the domain / e-mail whitelist are left alone, as in the scan.
- Every rule is applied, whatever its points: a blacklist hit is spam in the
  scan too ([scoring.md](scoring.md)). (Up to 2.0.0 a rule below the mailbox's
  spam threshold was skipped here.) SSH agents get `apply-blacklist
  --spam-threshold=0`, so an agent older than 3.5 does not skip such a rule
  either.
- Cost: IMAP searches `SINCE <30 days>`, exact rules also `FROM "<value>"`
  (server-side; a value that cannot be quoted safely is matched client-side
  only). Messages are processed **newest first**; wildcard/regex rules inspect
  at most 2000 messages of the window, and at most 500 are moved per rule and
  mailbox. A message that cannot be read or moved is reported and skipped,
  the pass goes on. SSH accounts get the
  rules synced first, then the agent's `apply-blacklist` reads only the headers
  of INBOX files modified in the last 30 days (at most 5000).
- SSH accounts need the agent redeployed (**Konta → Wdróż**) to get
  `apply-blacklist`; an old agent produces an error message, nothing else
  breaks.
- A Thunderbird/Outlook report triggers at most 10 retroactive passes per
  account and hour (`PluginApiController::RETRO_RATE_LIMIT`); above that the
  rule still applies to new mail at the next scan.
- Moved messages are logged in the score log (`Dziennik ocen`) as `spam` with
  the reason `retroactive blacklist:…` / `retroactive email_blacklist:…`.

## Full rescan

A scan only looks at **new** mail: a message that was checked once (marker /
IMAP cursor, the agent's `checked` table) is not checked again, so rules,
thresholds or patterns changed later do not touch mail that already sits in
INBOX. The retroactive blacklist pass above covers only new blacklist rules and
the last 30 days. The full rescan re-checks **every INBOX message** against
everything that is current: white / blacklists (domain, e-mail, wildcard /
regex), header heuristics, DNSBL, links, CERT list, attachments, Bayes,
per-mailbox thresholds.

Started by:

- **Konta → ↻ Przeskanuj całą skrzynkę ponownie** (account list, or the button
  below the account form) - per account, admin only;
- **Cotygodniowy ponowny skan całej skrzynki** in the account's *Ustawienia
  skrzynki* (off by default): once a week on the chosen day / hour (server
  time; empty = Sunday 02:00), queued by `antispam:rescan:due`, which the Docker
  scheduler runs hourly at minute 7 (`RESCAN_DUE=off` disables it; on a plain
  server: `7 * * * * php bin/console antispam:cron:run antispam:rescan:due`).
  A slot is caught up to 24 h late (scheduler down); after that the week is
  skipped. A failed rescan counts as done for its week (the error is on the
  account list);
- `php bin/console antispam:rescan:due --account=ID` (now, from the console);
- the Thunderbird plugin (1.4.0+): folder menu **Sprawdź cały folder Odebrane na
  serwerze** on an account logged in with its own mailbox (`POST
  /api/plugin/rescan`, 5 a day per mailbox, audit actor = the mailbox) - the
  plugin only polls the progress, the server moves the spam
  ([thunderbird.md](thunderbird.md#plugin-behaviour)).

How it runs (job `account.rescan`, [jobs.md](jobs.md)):

- **In the background, in batches** of `JOBS_BATCH_SECONDS` (120 s): the job
  re-queues itself until INBOX is done; the job page shows "Sprawdzono
  ponownie N wiadomości, zostało M" and the final counters (checked,
  whitelisted, blacklisted, moved to spam, quarantined, failed messages).
  **Anuluj** stops it after the current batch.
  - IMAP: the set of messages is fixed when the rescan starts (the UIDs the
    server lists then: `SEARCH ALL`, or `FETCH 1:*` when SEARCH answers with
    nothing although `STATUS` counts messages; a non-empty INBOX that cannot be
    listed fails the job instead of "finishing" with 0 checked). Later batches
    list only the next 500 UIDs at a time (`FETCH a:b`, wider over UID gaps),
    never everything above the cursor - on a 30 000-message INBOX that listing
    alone took most of every batch. The rescan has **its own cursor** in the job state - the
    account's incremental scan cursor and its last scan are not touched, so
    the regular scan (scan-all, **Skanuj**) goes on between two batches and
    handles the mail that arrives meanwhile. A changed UIDVALIDITY restarts
    the rescan from the oldest message.
  - SSH: agent 3.3+ command `rescan` ([agent.md](agent.md#rescan)); the agent
    remembers the progress in its own database (`rescan_done`), the first
    batch passes `--reset`. An older agent fails the job with "nie obsługuje
    polecenia "rescan" ... wdróż go ponownie (Konta → Wdróż)".
- **Interrupted rescans continue** (2.1.0):
  - a failed batch (connection drop, IMAP timeout, a `STATUS` without
    UIDVALIDITY) is retried from the same cursor after 1, 2, 5, 10 and 15 min
    (*Błąd przebiegu ... ponowna próba N/5*); the job fails only after that. A
    `STATUS` failure no longer restarts the rescan from the first message. An
    agent that does not know `rescan` fails at once (needs *Wdróż*, not time);
  - the progress is also stored on the account after every batch
    (`antispam_account.rescan_progress`: cursor + counters so far + job). A new
    rescan - panel button, weekly schedule, Thunderbird plugin - after a
    failed, cancelled or killed one **continues from there**, and its result
    adds up the counters of both parts. The account list shows *Niedokończony
    ponowny skan: sprawdzono N, zostało M* with **zacznij od nowa** (also on the
    account form), which drops the progress. SSH: the resumed job does not pass
    `--reset`, the agent continues its own `rescan_done` progress. A changed
    UIDVALIDITY still starts over. The progress is cleared when a rescan
    completes.
- **Cheaper checks** (2.1.0): DNSBL (the IP that delivered the message) is not
  looked up in a rescan - today's reputation says nothing about old mail and
  it cost DNS per message. Link domains are not looked up on the URI lists /
  Google Safe Browsing either while **Ustawienia → Filtr spamu → Ponowny skan
  całej skrzynki bez sprawdzania domen z linków** is on (default; config
  `rescan.skip_url_lookups`); the other link heuristics, the CERT list and the
  shared feed still run. A message already on a blacklist (spam anyway) skips
  the content checks - headers, links, attachments, CERT, feed, Bayes - so
  nothing but its envelope is fetched. Each batch logs its timing
  (`antispam: rescan batch`: seconds, listing seconds, messages, seconds per message).
- **Markers ignored, then set again**: a message is re-evaluated even if it
  was checked before; afterwards the normal scan skips it as usual.
- **Same lock as the scan**: while the scheduled scan (or the agent) scans the
  mailbox, the job waits and retries every 30 s (at most an hour).
- **One rescan per account**: dedupe key `account.rescan:<id>` - a second click
  (or the hourly schedule) while one is queued or running gets the existing
  job. A rescan and a normal scan of the same account are separate jobs.
- **Never deletes.** Spam is **moved** to `SPAM` (quarantine to `QUARANTINE`)
  even when the account has *Usuwaj spam* on. Reason: a rescan re-judges mail
  the user has already seen and kept, with rules that may have just changed
  (a too-broad wildcard, a lowered threshold); a move can be undone from the
  folder, a delete cannot. The same rule as the retroactive pass.
- **Per-mailbox settings** apply (thresholds, scoring switch - the account's
  *Ustawienia skrzynki* override, else global), as in a scan.
- **Out of the statistics**, like the initial scan: IMAP decisions are logged
  in the score log with `source = rescan` and `initial_scan = 1` (the
  dashboard, 30-day / daily stats, health "quarantined" counts and rule hit
  counters skip them; *Dziennik ocen* shows "ponowny skan, poza statystyką");
  the agent writes no `scan_log` entry. The account's *Ostatni skan* and the
  dashboard's recent scans are not changed - the rescan has its own
  `last_rescan_at` / `last_rescan_result`, shown under the account on the
  account list (time, counters or the error, link to the job).
- **Audit**: `account.rescan_queued` when queued (actor = admin, or
  `harmonogram` for the weekly one), `account.rescan` when it ends (`ok`,
  counters, error) - see [audit.md](audit.md).

Note: a message released from quarantine with **Przywróć** (without *Zawsze
akceptuj*) is judged again and can go back to quarantine if the rules still say
so - release with *Zawsze akceptuj* (sender on the whitelist) to keep it out.

**Ustawienia → Filtr spamu → Resetuj flagi sprawdzenia** still exists: it
forgets the markers of every IMAP mailbox at once, the next regular scan reads
every INBOX in full - counted in the statistics and with the account's delete
setting. For one mailbox prefer the full rescan.

## Periodic jobs and the cron log

`antispam:agent:scan-all` scans **every** mailbox: SSH accounts through the
agent, IMAP accounts and the legacy mailbox through the IMAP pipeline. SSH
accounts without a deployed agent are skipped, and so are mailboxes busy with a
panel scan job (shared per-mailbox lock, [jobs.md](jobs.md#concurrency-with-the-scheduled-scan)).
An IMAP mailbox gets at most `SCAN_MAX_SECONDS` (600) per run; a huge first scan
continues on the next run.

"Skanuj" in the panel does not run the scan in the request: it queues a
background job ([jobs.md](jobs.md)), which needs the job worker - the Docker
`scheduler` runs it; on a plain server add the `antispam:jobs:run --once` line
below.

Wrap periodic commands in `antispam:cron:run` to keep a log of them:

```bash
php bin/console antispam:cron:run antispam:agent:scan-all
```

Each run is stored in `antispam_cron_run` (command, start/end time, exit code,
output up to 60 kB) and shown on **Przegląd → Logi crona** (`/cron/logs`),
filterable by command and failures. A run without an end time older than two
hours is shown as *przerwane* (the process was killed). Entries older than 14
days are purged. The output is also printed, so `docker logs` / mail from cron
still work.

The Docker `scheduler` service (see [deployment.md](deployment.md)) already
runs every job through `antispam:cron:run`. On a plain server:

```
*/5 * * * * php /path/to/bin/console antispam:cron:run antispam:agent:scan-all
*/15 * * * * php /path/to/bin/console antispam:cron:run antispam:feed:sync
0 7 * * *   php /path/to/bin/console antispam:cron:run antispam:digest:send
0 0-6,8-23 * * * php /path/to/bin/console antispam:cron:run antispam:digest:send -- --scheduled-only
41 3 * * *  php /path/to/bin/console antispam:cron:run antispam:purge
7 * * * *   php /path/to/bin/console antispam:cron:run antispam:rescan:due
* * * * *   php /path/to/bin/console antispam:jobs:run --once
```

(The job worker is not wrapped in `antispam:cron:run` - it would fill the cron
log with a run per minute; its jobs are listed on **Zadania w tle**.)

`antispam:purge` keeps the tables that grow with every message bounded: score
log rows older than `scorelog.retention_days` (default **180**, `0` = keep
forever) and DNSBL cache entries older than the longest provider cache TTL (at
least one day). See [commands.md](commands.md#antispampurge). A purged score log
row also means an IMAP quarantine entry that old shows no reasons and gets no
"Zawsze akceptuj" button (see [quarantine-digest.md](quarantine-digest.md)).

Only `antispam:*` commands are accepted. Arguments for the wrapped command
go after `--` (`antispam:cron:run antispam:digest:send -- --scheduled-only`);
they are part of the command name stored in the log.
