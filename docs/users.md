# Users and roles

The panel supports several logins with two roles:

| Role | Sees | Can do |
|------|------|--------|
| `ROLE_ADMIN` | everything | everything (accounts, lists, DNSBL, feed, phishing, cron logs, plugin config, users) |
| `ROLE_USER` | only the mailboxes (accounts) assigned to them | see their own quarantine, SPAM folder and score log; release ("Przywróć"), "Zawsze akceptuj" (release + whitelist the sender) and delete quarantined messages, also in bulk per mailbox ("Usuń wszystkie wysokiego ryzyka", "Usuń wszystko z kwarantanny" - background job, result on `/my/jobs/{id}`); release from SPAM ("Przywróć do skrzynki", "Przywróć i zawsze akceptuj"); manage own sender white/blacklists (`/my/rules`); change their own password; set up 2FA |

## Login sources

`form_login` uses a chain provider with two sources, tried in this order:

1. **Legacy environment admin** - `ADMIN_USER` / `ADMIN_PASSWORD` (`ADMIN_PASSWORD_HASH`),
   `AntispamBundle\Security\AdminUserProvider`. Always `ROLE_ADMIN`, answered without
   a database query, so existing deployments keep working unchanged and can never lock
   themselves out (also before `antispam:db:upgrade` has created the user table).
   It is not stored in the database and is not editable in the UI; its login is
   reserved (a database user cannot use it). Its password is changed through the
   environment, as before.
2. **Database users** - `Entity\User`, table `antispam_user`, managed under
   **Ustawienia → Użytkownicy** (`/users`). Passwords are hashed with Symfony's `auto`
   hasher. Changing a password invalidates that user's sessions.

`role_hierarchy`: `ROLE_ADMIN` includes `ROLE_USER`.

## Data model

`antispam_user`: `id`, `username` (unique login, 3-180 chars `A-Za-z0-9._@+-`),
`password`, `role` (`ROLE_ADMIN` | `ROLE_USER`), `created_at`, and the nullable 2FA
columns `totp_secret` (encrypted, `enc:v1:`), `totp_enabled_at`, `totp_last_counter`,
`totp_backup_codes` (JSON list of bcrypt hashes) - see
[Two-factor authentication](#two-factor-authentication-2fa).

`antispam_user_account` (many-to-many, `ON DELETE CASCADE` on both sides): the
`Account`s a user owns. A user may have several mailboxes; a mailbox may be shared
by several users.

Why a link table instead of matching `User.email == Account.email`: the account is
the real unit of ownership (it carries the connection type and the quarantine key
`imap-<id>` / `ssh-<id>`), an address match would silently grant access when an
account e-mail is edited or duplicated, and one person often owns several mailboxes
or a login that is not an address. Score-log rows (`SpamScoreLog.accountEmail`) are
scoped through the e-mails of the assigned accounts.

The tables are part of the baseline migration, created by `antispam:db:upgrade` at boot
([migrations.md](migrations.md)).

## Ownership enforcement (no IDOR)

All rules live in `AntispamBundle\Security\MailboxAccess`; `MyController` calls it on
every request:

- **Quarantine listing** - `QuarantineService::getMailboxes()` is filtered to the keys
  of the user's accounts. A key must equal exactly `imap-<id>` / `ssh-<id>` of an
  assigned account (connection type included). The legacy config-based mailbox
  (`imap`) is admin-only.
- **Release / whitelist / delete** - the `mailbox` key from the POST body is checked
  before anything else; a foreign or malformed key gives HTTP 403. The message `id`
  is only resolved inside that mailbox's quarantine, so it cannot reach another
  mailbox. "Zawsze akceptuj" is refused server-side for high-risk messages (or
  messages no longer listed, or without a score log row of that mailbox -
  `score_unknown`, see [quarantine-digest.md](quarantine-digest.md)), the same rule
  the buttons follow.
- **Bulk delete** (`/my/quarantine/purge`, `mailbox` + `mode` `high_risk` / `all`):
  the key is checked the same way (403 for a foreign / legacy key, nothing queued),
  then a `quarantine.purge` job is queued with the user as requester; the job checks
  ownership again when it runs. The job page `/my/jobs/{id}` (and its status JSON)
  answers 404 for any job that is not a purge of an own mailbox queued by this user
  ([jobs.md](jobs.md#the-job-page)). See
  [spam-handling.md](spam-handling.md#bulk-deletion).
- **Score log** - `SpamScoreLogRepository::search()` gets an `accounts` filter (list
  of the user's account e-mails; an empty list matches nothing). A requested
  `account` that is not owned is dropped, not honoured. Tiles/stats and the account
  dropdown are computed from the same list. The "quarantine decisions" list of the
  admin page (global) is not exposed.
- Raw error text (hosts, paths) is not shown to users.

Everything outside `/my`, `/start` and the public routes falls through to the
`^/ -> ROLE_ADMIN` rule in `config/packages/security.yaml`.

## Routes

See [api.md](api.md): `/my/*`, `/start` (ROLE_USER) and `/users/*` (ROLE_ADMIN).

After login (`default_target_path: antispam_start`) administrators land on `/panel`,
users on `/my/quarantine` (after the 2FA code, when 2FA is on). The sidebar shows only
the user menu (Kwarantanna, Spam, Dziennik ocen, Moje reguły, Zmiana hasła,
Weryfikacja dwuetapowa) to `ROLE_USER`; "Spam" is the SPAM folder (`/my/spam`), the
score log stays under "Dziennik ocen".

## Own sender rules (`/my/rules`)

A user manages white/blacklist rules of **their own mailboxes**:

| List | Entity | Example values |
|------|--------|----------------|
| Zaufani nadawcy | `EmailWhitelist` | `szef@firma.pl`, `*@firma.pl` |
| Zaufane domeny | `Whitelist` | `firma.pl`, `*.firma.pl` |
| Blokowani nadawcy | `EmailBlacklist` | `promo@sklep.pl`, `*@*.ru` |
| Blokowane domeny | `Blacklist` | `spam.example`, `*.ru` |

They are the ordinary rule rows (same tables and consumers: scan, agent, plugins),
owned by the mailbox address - see [scoring.md](scoring.md#rule-ownership).

- **Owner** = one of the e-mails of the user's assigned accounts, never `*` (global
  rules stay admin-only) and never the legacy mailbox. An administrator opening the
  page may pick any account e-mail (still not `*`).
- **Pattern types**: exact and wildcard only (`Services\UserRulePolicy`); regex is
  refused server-side. A wildcard must end in a literal domain (whitelist: a real
  domain such as `*@firma.pl`; blacklist: at least a TLD such as `*.ru`), so `*`,
  `*@*` or `*.pl` cannot switch the filter off. Values are lower-cased; a leading
  `@` of a domain is dropped. At most 500 rules per list and mailbox.
- **Dedupe** like the admin forms (`RuleOwnership::findDuplicate`): a value already
  on the mailbox or on the global list is not added again.
- **Blacklist score** = `max(10, spam threshold)`, so a user blacklist rule is decisive.
- **No retroactive pass.** Unlike the admin forms, a user blacklist rule does not move
  mail that is already in INBOX - it applies from the next scan on (the page says so).
  Reason: `RetroactiveSpamService` logs in to the mailbox, and for SSH accounts its
  `apply-blacklist` re-applies *every* blacklist rule of the agent, not just the new
  one; reusing `DeferredRetroactivePass` would let a user click trigger a mailbox-wide
  move. Moving existing mail in bulk stays an admin action.
- **SSH+Maildir accounts**: the agent only knows synced rules. After every change
  `Services\DeferredAgentSync` pushes the rules (`AgentRulesExporter` + `import-rules`)
  to every deployed SSH account with that address in a **background job** (`account.sync`,
  one pending sync per account, [jobs.md](jobs.md)); the user is told it takes a few
  seconds. A failed sync is a failed job (visible on **Zadania w tle** and in the health
  check `jobs`), not shown to the user; the next admin sync / deploy sends the
  rules again. IMAP accounts read rules from the database on every scan.
- **Ownership / IDOR**: delete takes `list` + `id`; the rule is looked up in that list
  only and deleted only when its stored owner is one of the user's mailbox e-mails - a
  foreign mailbox's rule and a global (`*`) rule give HTTP 403. Adding with a foreign or
  `*` owner gives 403 as well (never silently "corrected"). POST + CSRF (`my_rules`).
- Audited as `rule.add` / `rule.delete` with `details.source = "my"`.

## Releasing mail from SPAM (`/my/spam`)

Lists the newest 100 messages of the `SPAM` folder of every own mailbox (IMAP accounts:
the folder from the settings, `InboxService::getSpamFolderName()`; SSH accounts:
`~/Maildir/.SPAM` via the agent's `spam-list`), with score and reasons from the score
log (IMAP: newest `spam` decision of the same mailbox, sender and subject; agent: its
`score_log.file` link).

- **Przywróć do skrzynki** - moves the message back to INBOX and marks it checked
  (IMAP: `MessageService::setAsChecked` for that mailbox; agent: `checked` table), so the
  next scan does not move it back.
- **Przywróć i zawsze akceptuj** - the same plus an exact e-mail whitelist rule for the
  sender on that mailbox (`QuarantineService::whitelistSender`); for SSH the agent adds it
  locally (`--whitelist`) and a deferred rules sync follows. Refused server-side (fail
  closed) for high-risk messages, for messages without a score log row (`score_unknown`)
  and for messages no longer listed - like the quarantine.
- IMAP ids are UIDs; the form carries the folder's UIDVALIDITY and release refuses to act
  when it changed. SSH ids are Maildir base names validated by the agent.
- The mailbox key (`imap-<id>` / `ssh-<id>`) is checked with `MailboxAccess` first (403
  for a foreign key); the id is only looked up inside that mailbox's SPAM folder. POST +
  CSRF (`my_spam_action`). No delete action here: spam is kept until the user's mail
  client or the server removes it.
- Audited as `spam.release` / `spam.whitelist` (`details`: `source: my`, `mailbox_id`, `ok`).
- SSH accounts need agent **3.1** (redeploy: Konta → Wdróż); with an older agent the page
  shows an error for that mailbox only.
- The admin page **Skrzynki → Folder spamu** (legacy mailbox) is unchanged.

## Two-factor authentication (2FA)

TOTP (RFC 6238: SHA-1, 6 digits, 30 s, ±1 step), implemented in `Security\TwoFactor`
(no bundle: scheb/2fa-bundle needs the user class to carry the secret, which the env
admin's `InMemoryUser` cannot). The QR code is rendered locally as SVG
(`bacon/bacon-qr-code`) and embedded as a `data:` image - the secret never goes to an
external service.

**Setup** (`/my/2fa`, every logged-in database user, admins included): scan the QR code
(or type the key), confirm with a current code - only then is the secret stored
(encrypted with `CryptoService`, derived from `APP_SECRET`; changing `APP_SECRET` makes
TOTP codes fail, backup codes keep working). 10 **backup codes** are shown once (stored as
bcrypt hashes, each usable once); "Wygeneruj nowe kody" replaces them (password + code).
**Disable** needs the current password + a code (TOTP or backup) and is blocked for
admins while 2FA is required.

**Login**: `form_login` checks the password as before; then `TwoFactorGuard`
(`kernel.request`, after the firewall) redirects every non-public page to `/2fa` until a
valid code (or backup code) was entered in this session. The session marker is bound to
the user and dropped on every new login (fail closed: no marker = code required).
`/2fa`, `/logout` and the public paths (`PUBLIC_ACCESS` in `access_control`) stay
reachable. Each TOTP step is accepted once (`totp_last_counter`, replay protection).

**Throttling**: every code check (login step, enable, disable, new backup codes) goes
through the `two_factor_code` rate limiter - 5 wrong codes per login per 15 minutes
(`framework.rate_limiter`, keyed by login only: whoever reaches this step knows the
password and may rotate IPs). A successful code resets it. The password step keeps
`login_throttling`.

**Enforcement**: Ustawienia → Użytkownicy → "Wymagaj 2FA dla administratorów" (config
`security.2fa_required_admins`). A database admin without 2FA is then sent to `/my/2fa`
after login and can use nothing else until 2FA is on.

**Environment admin** (`ADMIN_USER`): not in the database, so it cannot enrol in the
panel. Set `ADMIN_TOTP_SECRET` (base32, from `php bin/console antispam:2fa:secret`; add it
to the authenticator app by hand or from the printed `otpauth://` URI) to require a code
for it. It has no backup codes (recovery = change or clear the variable) and its replay
counter lives in the config table (`security.2fa_env_admin_counter`). Without the
variable it logs in with the password only, **also when 2FA is required** - enforcement
never locks out the account that exists so a deployment cannot lock itself out; the users
page shows whether the variable is set. Recommended: create a database administrator,
enable 2FA for it and keep the env admin for emergencies, with `ADMIN_TOTP_SECRET` set.

**Admin reset** (lost phone and backup codes): Użytkownicy → "Reset 2FA" clears the
secret and backup codes (POST + CSRF); the user logs in with the password and may set up
2FA again (an admin is forced to, while 2FA is required).

**Audit**: `auth.2fa_verified` (method `totp` / `backup`), `auth.2fa_failed` (step
`login` / `enable` / `disable` / `backup_codes`, reason `wrong_code` / `wrong_password` /
`throttled`), `auth.2fa_enabled`, `auth.2fa_disabled`, `auth.2fa_backup_codes`,
`auth.2fa_reset`; the policy switch is `settings.save` (`target_id` `2fa_policy`). Codes
are never logged.

**Not covered**: remembered / trusted devices, WebAuthn, 2FA for the plugin API
(`/api/plugin`, its own token login) and the signed `/q/` digest links. A configuration
backup does not carry the 2FA columns: users restored from a backup set 2FA up again.

## Administration notes

- Admins cannot delete their own account or drop their own admin role.
- A new user needs a password (min. 10 characters) and, for `ROLE_USER`, at least
  one mailbox to see anything.
- Deleting an `Account` removes it from its users automatically.
- Not covered: password reset by e-mail, disabling a user without deleting.
- The signed `/q/` digest links are independent of logins and keep working as before.
