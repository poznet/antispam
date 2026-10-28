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
| Legacy mailbox (Ustawienia → E-mail) | *Usuwaj spam na stałe* in Ustawienia → Filtr spamu (config `delete`) |
| SSH+Maildir account | always moved to `~/Maildir/.SPAM` (the agent never deletes spam) |

The `SPAM` and `QUARANTINE` folders are created on first use. In IMAP the
message is moved with `MOVE`/`COPY`+`\Deleted` and the INBOX is expunged at the
end of the scan.

`MoveToSpam` and `ApplyScoreDecision` act on the IMAP connection the message
came from (`MessageEvent::getConnection()`), so every IMAP account uses its own
folders. `ImapScanService` runs the pipeline for both IMAP accounts and the
legacy mailbox.

## Quarantine

Quarantine is **not deletion**: the message is moved out of INBOX into the
`QUARANTINE` folder (`~/Maildir/.QUARANTINE` for SSH accounts) and stays there
until someone acts on it. Nothing removes quarantined mail automatically.

Every quarantined message can be released:

- in the panel: **Skrzynki → Kwarantanna** - *Dostarcz* (back to INBOX),
  *Zawsze akceptuj* (back to INBOX + sender on the e-mail whitelist, hidden for
  high-risk messages), *Usuń* (permanent);
- from the [quarantine digest](quarantine-digest.md) e-mail (signed one-click
  links, same three actions).

A released message is marked as checked, so the next scan does not quarantine
it again. The page covers the legacy mailbox (`imap`), every IMAP account
(`imap-<id>`) and every SSH account with a deployed agent (`ssh-<id>`).

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
last 30 days to `SPAM` in every mailbox owned by the rule's account e-mail. The
panel shows how many were moved; the plugin API returns `moved_existing`.

Rules and limits:

- Mail is always **moved**, never deleted, even when deletion is on - a mistake
  can be undone from the SPAM folder.
- Senders on the domain / e-mail whitelist are left alone, as in the scan.
- With scoring enabled, a rule below the spam threshold only adds points in
  the scan, so it is not applied retroactively (the panel says so).
- Cost: IMAP exact rules use a server-side `SEARCH FROM`; wildcard/regex rules
  search `SINCE <30 days>` and check at most 500 messages. SSH accounts get the
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
```

Only `antispam:*` commands are accepted.
