# Account statistics ("Statystyki konta")

*Konta → Statystyki* (`/account/stats/{id}?days=1|7|30|90|365|0`, admin; also
from the account form): what the scans of one mailbox found and where it went.
Users (ROLE_USER) have the same page for their assigned mailboxes under *Moja
poczta → Statystyki* (`/my/stats/{id}`, another account's id = 404, agent
errors without host details, no admin links). Both are built by
`AccountStatsPage::build()`.

## Scan counters (IMAP and SSH)

Every scan pass adds its counters to the account's row of the day in
`antispam_account_daily_stat` (`AccountStatsService::record()`, entity
`AccountDailyStat`, migration `Version20261119180000`), one row per account,
day and kind:

| kind | written by |
|---|---|
| `scan` | `AccountScanner::scan()` (scan-all, panel *Skanuj* job), `antispam:agent:scan` |
| `initial` | the same, while the first scan of a new mailbox is unfinished |
| `rescan` | `AccountScanner::rescan()` (every batch of a full rescan) |
| `retro` | `RetroactiveSpamService::applyRule()` - mail moved to SPAM after a new blacklist rule |

Counters: `passes`, `checked`, `skipped`, `whitelisted`, `blacklisted`,
`quarantined`, `moved_to_spam` (IMAP with *Usuwaj spam*: deleted), `move_failed`,
`errors`. Written with plain DBAL (update, else insert) - works after an
EntityManager reset, never fails the scan. Never pruned (one row per day and
kind); deleting the account drops its rows. Collected from this version on:
older scans only exist in the score log.

The page shows the period totals (tiles with the share of the checked mail),
a daily chart of new mail (kinds `scan` + `initial`, last 30 / 90 days - a rescan would flatten it), the totals per kind, blacklist hits,
skipped, failed moves, errors and the plugin reports (`antispam_plugin_report`).

## Dashboard "Dzisiaj"

The admin dashboard (`/panel`) shows today's counters summed over all accounts
(`AccountStatsService::dayTotals()`): messages checked (new mail = `scan` +
`initial`), scan passes, accounts scanned, spam / blacklisted / not moved,
quarantined, whitelisted, scan errors, rescan volume, plus plugin checks of the
day from the score log (`source = plugin`); each tile shows yesterday's value
for comparison.

## Per-message detail

- **IMAP**: the score log of the mailbox (`antispam_spam_score_log`, only when
  logging is on in *Ustawienia → Filtr spamu*): decisions per source (scan,
  first scan, rescan, retroactive, plugin check), outcomes (moved to SPAM /
  quarantine, deleted, failed move), top 15 senders / sender domains / rules
  and rule categories of spam + quarantine (`AccountStatsService::aggregate()`,
  newest 20 000 rows), the 30 newest spam / quarantine entries, link to the
  full *Dziennik ocen* of the mailbox.
- **SSH**: the agent keeps that log itself. *Pobierz statystyki z agenta*
  (`?agent=1`) runs `stats --days=N` over SSH (agent 3.9+,
  `SshService::runStats()`, docs/agent.md) and shows the same tables; plugin
  checks of the mailbox (server score log) are listed below it.
