# Audit log ("Dziennik audytu")

Who did what, when and from where - for RODO / compliance questions ("who released
this message?", "who removed that blacklist rule?", "who logged in from this IP?").
Page: **Przegląd → Dziennik audytu** (`/audit`, ROLE_ADMIN only).

## What is recorded

| Action key | When | Target / mailbox / details |
|------------|------|----------------------------|
| `auth.login` | panel login (form_login) | user; firewall |
| `auth.login_failed` | failed panel login (also throttled) | the login that was typed; `reason` = exception class or `throttled` |
| `auth.logout` | logout | user |
| `auth.2fa_verified` | correct 2FA code at login (`/2fa`) | user; `method` = `totp` / `backup` |
| `auth.2fa_failed` | wrong / throttled 2FA code, wrong password on a 2FA form | user; `step` = `login` / `enable` / `disable` / `backup_codes`, `reason` = `wrong_code` / `wrong_password` / `throttled` |
| `auth.2fa_enabled`, `auth.2fa_disabled`, `auth.2fa_backup_codes` | own 2FA (`/my/2fa`): turned on, off, new backup codes | user |
| `auth.2fa_reset` | admin reset of a user's 2FA (`/users/2fa-reset/{id}`) | user id, login |
| `rule.add`, `rule.delete` | white/blacklist rule (domain and e-mail lists; admin lists and the user's own rules on `/my/rules` with `source: my`) | list type + rule id, value, owner mailbox (`*` = all); pattern type, score, `source` |
| `rule.import` | bulk import (`/bulk/import/{type}`) | list type, owner; added / skipped counts |
| `rule.make_global` | **Zmień na: Wszystkie skrzynki** on a rule list (one entry per changed rule, also in bulk) | list type + rule id, value, mailbox `*`; `from` (old owner), `merged` (deleted into an existing global rule), pattern type, score (blacklists) |
| `rules.make_global` | `antispam:rules:make-global` (not with `--dry-run`) | owner; moved / merged counts; actor `cli` |
| `quarantine.release`, `quarantine.whitelist` ("Zawsze akceptuj"), `quarantine.delete` | admin panel (`source: panel`), user area `/my` (`source: my`), digest link `/q/` (`source: digest`, actor `link z raportu`) | message id, sender, mailbox address, quarantine key; `ok` = whether it worked (failed attempts are recorded too) |
| `quarantine.blacklist` | *Do czarnej listy* on a quarantined message (panel `source: panel`, user area `source: my`) | message id, sender, mailbox, quarantine key; `ok`, `moved_to_spam` (its quarantined mail moved to SPAM), `rule_added` (false = the rule existed); a new rule is also `rule.add` with `source: quarantine` |
| `quarantine.purge_queued`, `quarantine.purge` | bulk delete "Usuń wszystkie wysokiego ryzyka" / "Usuń wszystko z kwarantanny" (`/spambox/quarantine/purge[-all]`, `/my/quarantine/purge`): queued, and the job's end (worker, actor = requester) | target `quarantine` / mailbox key, mailbox address; `job`, `mode` (`high_risk` / `all` / `min_score` + `min_score`), `source` (`panel` / `my`); queued: `shown` (count in the confirmation); end: `ok`, `total`, `deleted`, `skipped`, `failed`, `error` |
| `spambox.restore` | restore from the legacy SPAM / QUARANTINE folder | message number, folder |
| `spam.release`, `spam.whitelist` ("Przywróć i zawsze akceptuj") | user area SPAM folder `/my/spam` | message id (IMAP UID / Maildir name), sender, mailbox address; `source: my`, `mailbox_id` (`imap-<id>` / `ssh-<id>`), `ok` (failed / refused attempts too) |
| `plugin.login`, `plugin.login_failed` | plugin login (`/api/plugin/login`) | mailbox address typed / logged in |
| `plugin.report` | spam / not-spam report from a plugin | sender, mailbox; verdict, learned rules, `scope: report_only` and `reported_from` (message from another mail client account, plugin 1.3.0+; only when set); actor = plugin account (or anonymous) |
| `plugin.phishing` | phishing report from a plugin | phishing report id, sender, mailbox; duplicate, client, `scope` / `reported_from` as for `plugin.report` |
| `phishing.update`, `phishing.block`, `phishing.delete`, `phishing.eml_download`, `phishing.forward` | `/phishing/*` | report id, sender, mailbox; status from/to, blocked value, rule id; forward result, recipients, resend/bulk |
| `backup.export`, `backup.import` | Kopia zapasowa | file name, with/without secrets, format; import mode, sections, created/updated/deleted/skipped counts |
| `settings.save` | Filtr spamu, Wspólna baza spamu, Raport kwarantanny, Wtyczki pocztowe, Konfiguracja (stara), Lista CERT, Przekazywanie phishingu (`phishing_forward`), "Wymagaj 2FA dla administratorów" (`2fa_policy`, `required`), Logowanie OAuth (`oauth`) | `target_id` = page; submitted field **names**, `secrets_changed` = names of secret fields that were set or cleared |
| `settings.digest_send` | "Wyślij teraz" of the digest page | as above |
| `settings.uncheck_all`, `settings.reset_counters` | maintenance buttons of Filtr spamu | - |
| `account.add`, `account.edit`, `account.delete`, `account.deploy`, `account.sync`, `account.host_key_reset` | `/account/*` | account id, name, mailbox; connection type, field names, `ok`; `account.edit` also `settings_overrides` (per-mailbox overrides with values), `settings_changed` and `auto_rescan` (weekly rescan day / hour or `false`) |
| `account.rescan_queued`, `account.rescan` | `/account/rescan/{id}`, `antispam:rescan:due` (actor `harmonogram`), job worker | account id, name, mailbox; `job`, `trigger` (`panel` / `schedule` / `cli`); `account.rescan` (job end) also `ok`, `total`, `checked`, `whitelisted`, `blacklisted`, `quarantined`, `moved_to_spam`, `error` |
| `account.oauth_connected`, `account.oauth_disconnected` | OAuth consent finished / tokens deleted (`/account/oauth/*`, [oauth.md](oauth.md)) | account id, name, mailbox; `provider`, `oauth_username` |
| `account.oauth_refresh_failed` | token renewal (refresh / client credentials) failed - once per new error, also from cron | account; `provider`, `method`, `error_code` (`invalid_grant`...), `reconnect`, `message` |
| `user.add`, `user.edit`, `user.delete` | `/users/*` | user id, login; role, assigned mailboxes, `password_changed` (bool) |
| `user.password_change` | own password (`/my/password`) | user |
| `dnsbl.add`, `dnsbl.toggle`, `dnsbl.delete` | `/dnsbl/*` | provider id, zone; name, score, enabled |
| `cert.sync` | manual "Pobierz teraz" on `/cert/` | result message; `ok` |
| `job.cancel` | **Anuluj** on a background job page (`/jobs/{id}`) | job id, label, mailbox; job type, `state` (`cancelled` / `cancel_requested`) |
| `bayes.trained` | `antispam:bayes:train` | folders, mailbox; learned / skipped / failed per verdict |
| `bayes.reset` | "Wyczyść bazę Bayesa" on Filtr spamu | deleted rows |

Not recorded: read-only pages, connection tests, scans, cron jobs (they have the
cron log), the plugin `/check` endpoint and the score pipeline itself (score log).

**Never stored:** passwords, API keys, feed keys, tokens, message content. Settings
are recorded by field name only; `AuditLogger::sanitize()` additionally drops any
detail key that looks like a secret (`pass`, `secret`, `token`, `api_key`, `*_key`,
`hash`, `credential`, `raw`) and shortens strings (300 chars, JSON max 4000 bytes).

## Columns (`antispam_audit_log`)

| Column | Content |
|--------|---------|
| `created_at` | server time |
| `actor` | login, env admin login, plugin mailbox, `link z raportu`, `cli`, or the typed login of a failed attempt |
| `actor_type` | `user` (database user), `env_admin` (ADMIN_USER), `anonymous`, `digest_link`, `plugin`, `cli` |
| `role` | `ROLE_ADMIN` / `ROLE_USER` when known |
| `ip` | `Request::getClientIp()` - the real client only when the reverse proxy is trusted (`SYMFONY_TRUSTED_PROXIES`, see [deployment.md](deployment.md#behind-a-reverse-proxy-nginx)); empty for console commands |
| `action` | key from the table above |
| `target_type`, `target_id`, `target_label` | what was acted on (e.g. `whitelist` / `12` / `firma.pl`) |
| `mailbox` | the mailbox concerned (`*` = all mailboxes) |
| `details` | short JSON |

Indexes on `created_at`, `action`, `actor`, `mailbox`. The table is part of the
baseline migration (`antispam:db:upgrade` at boot, [migrations.md](migrations.md)).

## Design

- `Services\AuditLogger::log(action, targetType:, targetId:, label:, mailbox:, details:, actor:, actorType:)`
  resolves the actor (security token: `Entity\User` -> `user` + role, the in-memory
  env admin -> `env_admin`, no token -> `anonymous`, console without a request ->
  `cli`) and the IP, and inserts the row with **plain DBAL** - outside the ORM unit of
  work, so logging never flushes or loses the caller's pending entity changes.
- **Best effort:** every failure (table missing, database down) is caught and logged
  to the application log (`Audit log write failed`); the audited action goes on.
- Controllers use `Controller\AuditTrait` (`use AuditTrait;` + one `$this->audit(...)`
  line per action). The logger is a lazily subscribed, optional service of the
  controller's locator, so constructors are unchanged; a controller without it
  (hand-wired unit tests) just does not audit.
- `AuditLogger::quarantine()` maps the three quarantine actions and resolves the
  mailbox address from the quarantine key (`imap`, `imap-<id>`, `ssh-<id>`).
- `Security\AuditSecuritySubscriber` listens to `LoginSuccessEvent`,
  `LoginFailureEvent` and `LogoutEvent` (registered on every firewall dispatcher by
  Symfony). The password is never read.
- Entries are written after the change succeeded (rules, users, accounts...) or after
  the attempt with `ok: true|false` (quarantine, deploy, sync, CERT sync). CSRF / 403
  refusals happen before and are not audit entries.

## Page and export

`/audit` - newest first, 50 per page. Filters (GET): `from`, `to` (`Y-m-d`, both
inclusive), `actor` (substring), `action` (exact key, or a group like `rule.` /
`quarantine.`), `mailbox` (substring), `page`.

`/audit/export.csv` - the same filters, newest 50 000 rows, UTF-8 with BOM, `;`
separated (opens directly in Excel / LibreOffice). Cells starting with `= + - @`
are prefixed with `'` (CSV formula injection).

Both routes need `ROLE_ADMIN`: the catch-all `access_control` rule and
`#[IsGranted('ROLE_ADMIN')]` on `AuditController`. The ROLE_USER menu has no entry.

## Retention

Config key `audit.retention_days` (default **365**, `0` = keep forever), applied by
`antispam:purge` (daily in the Docker scheduler). `--days` of that command only
concerns the score log; `--dry-run` counts audit rows too. Set it e.g. with:

```sql
INSERT INTO config (name, value) VALUES ('audit.retention_days', '730');
```

(or `UPDATE config SET value = '730' WHERE name = 'audit.retention_days'` when it exists).

## Tests

`Tests/Services/AuditLoggerTest.php` (SQLite: actor / IP / secrets / failures /
purge / CSV / filters), `Tests/Controller/AuditTrailTest.php` (every area writes
its entry), `Tests/Security/AuditAccessTest.php` (ROLE_ADMIN only, wiring, page render).

## Actions run as background jobs

`account.deploy`, `account.sync`, `account.rescan`, `cert.sync` and the bulk `phishing.forward` run in the
background job worker ([jobs.md](jobs.md)). Their entries are written when the job
finishes, with the user who clicked as the actor (copied to the job when it was queued)
and `job: <id>` in the details; the IP column is empty (the worker has no request).

