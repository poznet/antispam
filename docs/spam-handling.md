# What happens to spam

How detected mail leaves INBOX, how the quarantine works, how a new blacklist
rule is applied to mail that already arrived, and where to see what the
periodic jobs did.

## Spam: move or delete

Every mailbox ends a scan with one of three decisions per new message
(see [scoring.md](scoring.md)):

| Decision | Score | What happens |
|----------|-------|--------------|
| ham | below the quarantine threshold | stays in INBOX |
| quarantine | quarantine threshold ≤ score < spam threshold | moved to `QUARANTINE` |
| spam | ≥ spam threshold (or a hard hit: exact blacklist without scoring, ClamAV/VirusTotal) | moved to `SPAM`, or deleted |

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
  high-risk messages), *Usuń* (permanent);
- from the [quarantine digest](quarantine-digest.md) e-mail (signed one-click
  links, same three actions).

A released message is marked as checked, so the next scan does not quarantine
it again. The page covers the legacy mailbox (`imap`), every IMAP account
(`imap-<id>`) and every SSH account with a deployed agent (`ssh-<id>`).

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

- on **Blacklista domen** / **Blacklista e-mail** in the panel, or
- by a logged-in Thunderbird plugin user reporting spam (which adds an exact
  e-mail blacklist rule, see [thunderbird.md](thunderbird.md)),

`RetroactiveSpamService::applyRule()` moves matching INBOX messages from the
last 30 days (every rule type) to `SPAM` in every mailbox owned by the rule's account e-mail (a
global rule - owner **Wszystkie skrzynki**, `*` - goes through every account
and the legacy mailbox, one after another in the same request; see
[scoring.md](scoring.md#rule-ownership)). The
panel shows how many were moved. For a plugin report the pass runs after the
response has been sent (`DeferredRetroactivePass` on `kernel.terminate`; the
usual IMAP timeouts apply and `set_time_limit(0)` keeps mod_php's
`max_execution_time` from cutting the pass short), so the plugin is not kept
waiting; the API only answers
`"retroactive": "scheduled"` and the result goes to the application log and
the score log. On Apache + mod_php (the Docker image) such a response gets
`Content-Length` + `Connection: close` and no mod_deflate, so the client sees
its end before the script finishes.

Rules and limits:

- Mail is always **moved**, never deleted, even when deletion is on - a mistake
  can be undone from the SPAM folder.
- Senders on the domain / e-mail whitelist are left alone, as in the scan.
- With scoring enabled, a rule below the spam threshold only adds points in
  the scan, so it is not applied retroactively (the panel says so). The check
  is **per mailbox** with its effective settings (account override -> global):
  a global rule with 6 points is applied to a mailbox with spam threshold 6
  and skipped for one with 10 ("próg spamu skrzynki jest wyższy: ola@firma.pl
  (10)"); scoring switched off for a mailbox applies every rule there. SSH
  agents get the mailbox's threshold in `apply-blacklist --spam-threshold`.
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

## Periodic jobs and the cron log

`antispam:agent:scan-all` scans **every** mailbox: SSH accounts through the
agent, IMAP accounts and the legacy mailbox through the IMAP pipeline. SSH
accounts without a deployed agent are skipped.

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
```

`antispam:purge` keeps the tables that grow with every message bounded: score
log rows older than `scorelog.retention_days` (default **180**, `0` = keep
forever) and DNSBL cache entries older than the longest provider cache TTL (at
least one day). See [commands.md](commands.md#antispampurge). A purged score log
row also means an IMAP quarantine entry that old shows no reasons and gets no
"Zawsze akceptuj" button (see [quarantine-digest.md](quarantine-digest.md)).

Only `antispam:*` commands are accepted. Arguments for the wrapped command
go after `--` (`antispam:cron:run antispam:digest:send -- --scheduled-only`);
they are part of the command name stored in the log.
