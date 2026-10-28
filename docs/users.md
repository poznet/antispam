# Users and roles

The panel supports several logins with two roles:

| Role | Sees | Can do |
|------|------|--------|
| `ROLE_ADMIN` | everything | everything (accounts, lists, DNSBL, feed, phishing, cron logs, plugin config, users) |
| `ROLE_USER` | only the mailboxes (accounts) assigned to them | see their own quarantine, spam and score log; release ("Przywróć"), "Zawsze akceptuj" (release + whitelist the sender) and delete quarantined messages; change their own password |

## Login sources

`form_login` uses a chain provider with two sources, tried in this order:

1. **Legacy environment admin** - `ADMIN_USER` / `ADMIN_PASSWORD` (`ADMIN_PASSWORD_HASH`),
   `AntispamBundle\Security\AdminUserProvider`. Always `ROLE_ADMIN`, answered without
   a database query, so existing deployments keep working unchanged and can never lock
   themselves out (also before `doctrine:schema:update` has created the user table).
   It is not stored in the database and is not editable in the UI; its login is
   reserved (a database user cannot use it). Its password is changed through the
   environment, as before.
2. **Database users** - `Entity\User`, table `antispam_user`, managed under
   **Ustawienia → Użytkownicy** (`/users`). Passwords are hashed with Symfony's `auto`
   hasher. Changing a password invalidates that user's sessions.

`role_hierarchy`: `ROLE_ADMIN` includes `ROLE_USER`.

## Data model

`antispam_user`: `id`, `username` (unique login, 3-180 chars `A-Za-z0-9._@+-`),
`password`, `role` (`ROLE_ADMIN` | `ROLE_USER`), `created_at`.

`antispam_user_account` (many-to-many, `ON DELETE CASCADE` on both sides): the
`Account`s a user owns. A user may have several mailboxes; a mailbox may be shared
by several users.

Why a link table instead of matching `User.email == Account.email`: the account is
the real unit of ownership (it carries the connection type and the quarantine key
`imap-<id>` / `ssh-<id>`), an address match would silently grant access when an
account e-mail is edited or duplicated, and one person often owns several mailboxes
or a login that is not an address. Score-log rows (`SpamScoreLog.accountEmail`) are
scoped through the e-mails of the assigned accounts.

The schema is created by `doctrine:schema:update --force` at boot (no migration needed).

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
users on `/my/quarantine`. The sidebar shows only the user menu (Kwarantanna, Spam,
Dziennik ocen, Zmiana hasła) to `ROLE_USER`.

"Spam" for a user is the score log filtered by `decision=spam`: the contents of the
IMAP SPAM folder are only readable for the legacy mailbox (admin), so the log is the
per-mailbox source.

## Administration notes

- Admins cannot delete their own account or drop their own admin role.
- A new user needs a password (min. 10 characters) and, for `ROLE_USER`, at least
  one mailbox to see anything.
- Deleting an `Account` removes it from its users automatically.
- Not covered: password reset by e-mail, disabling a user without deleting, login
  throttling beyond what the firewall offers.
- The signed `/q/` digest links are independent of logins and keep working as before.
