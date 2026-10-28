# OAuth2 (XOAUTH2) IMAP login - Microsoft 365 and Gmail

Microsoft 365 (Exchange Online) has turned off password login (Basic Auth) for
IMAP, and Google Workspace accepts only OAuth or app passwords. IMAP accounts can
therefore log in with an **OAuth2 access token** (SASL `XOAUTH2`) instead of a
password. Everything that works for a password IMAP account works for an OAuth
account too: scanning (cursor, pipeline, move to SPAM / QUARANTINE, delete),
quarantine and SPAM release (panel, `/my`, digest links), the retroactive
blacklist, the connection test and the health probe.

## Login methods (`imap_auth_method`)

| Value | Provider | Flow | Who consents | Refresh |
| --- | --- | --- | --- | --- |
| `password` (or `NULL`) | any IMAP server | login + password (ext-imap) | - | - |
| `oauth_microsoft` | Microsoft 365 / Outlook.com | authorization code + PKCE, scopes `openid email profile offline_access https://outlook.office.com/IMAP.AccessAsUser.All` | the mailbox user (or an admin for the whole tenant) | refresh token (rotated by Microsoft) |
| `oauth_microsoft_app` | Microsoft 365 | client credentials, scope `https://outlook.office365.com/.default` | tenant admin (`IMAP.AccessAsApp` + Exchange service principal + mailbox permission) | new token per hour, no refresh token |
| `oauth_google` | Gmail / Google Workspace | authorization code + PKCE, scopes `openid email https://mail.google.com/`, `access_type=offline`, `prompt=consent` | the mailbox user | refresh token |

Why these: the **delegated authorization code flow** is the one both providers
document for IMAP, needs no admin tooling and works for a single mailbox. PKCE is
added although the app is a confidential client (client secret), as both
providers recommend. **App-only (client credentials)** is offered for Microsoft
365 only: an admin who manages many mailboxes grants access once in PowerShell
instead of logging in as every user. Google's equivalent (a service account with
domain-wide delegation) is not implemented - the delegated flow works for
Workspace too. The device-code flow is not used (it would need a polling UI).

## How it works

- **Provider apps are global** (one Entra app, one Google OAuth client):
  *Ustawienia → Logowanie OAuth* (`/config/oauth/`, `OAuthController::settingsAction`),
  stored in the `config` table: `oauth.microsoft.client_id`,
  `oauth.microsoft.client_secret` (encrypted), `oauth.microsoft.tenant`
  (default `common`), `oauth.google.client_id`, `oauth.google.client_secret`
  (encrypted). The page shows the redirect URI to register and the setup steps.
- **Per account:** login method, optional Microsoft tenant override (an MSP
  serving several tenants with one multi-tenant app), and the tokens.
- **Połącz** (`GET /account/oauth/connect/{id}?_token=...`, CSRF token
  `account_action_{id}`) creates `state` (32 random bytes) and a PKCE verifier,
  keeps them in the session (`antispam_oauth_pending`, max 5, 15 minutes,
  single use) and redirects the browser to the provider. It is a link, not a
  form: the CSP `form-action 'self'` blocks a form post that redirects to
  another origin.
- **Callback** `GET /account/oauth/callback` (ROLE_ADMIN, the session cookie is
  `SameSite=Lax` so it comes along on the top-level redirect back): the `state`
  must match a pending entry of this session (constant-time compare), `error`
  from the provider is shown, the code is exchanged with the verifier and the
  client secret, the address is taken from the `id_token` (`email`, else
  `preferred_username` / `upn`; read directly from the token endpoint over TLS,
  OIDC Core 3.1.3.7). Gmail requires the XOAUTH2 user to be the token owner, so a
  different Google account than the account's login is refused. For Microsoft a
  different address is allowed (shared mailbox) with a warning.
- **Redirect URI** = `plugin.public_url` (Ustawienia → Wtyczki pocztowe) or the
  request's scheme + host, + `/account/oauth/callback`, e.g.
  `https://antispam.example.pl/account/oauth/callback`. Both providers need
  `https://` (localhost excepted). Set the public URL so the URI does not
  depend on the address the panel was opened with; behind a TLS proxy set
  `SYMFONY_TRUSTED_PROXIES` too.
- **Tokens** (`OAuthTokenManager`): the access token is stored encrypted with
  its expiry and reused until 5 minutes before it expires; then it is renewed
  with the refresh token (or client credentials). Renewal is serialized per
  account with a file lock in `var/data/locks` and the stored tokens are read
  again after taking the lock, so parallel processes (cron scan, panel, digest)
  never use a refresh token that Microsoft has already rotated. Writes go
  through DBAL, outside the caller's unit of work. A token the IMAP server
  rejects is renewed once and the login retried.
- **Errors** of a renewal are stored in `oauth_error` / `oauth_error_at` and
  shown in the account list (red badge), on the edit page, in **Stan systemu**
  (account check FAIL) and in `antispam:doctor` (check `oauth`). Each new error
  is audited once (`account.oauth_refresh_failed`), not on every cron tick. A
  successful renewal clears the error.
- **Rozłącz** (`POST /account/oauth/disconnect/{id}`, CSRF) deletes the tokens
  on this server. To revoke the grant at the provider too:
  myaccount.google.com/permissions, myapps.microsoft.com, or Entra → Enterprise
  applications → the app → Users / Permissions.
- Changing the login method (or provider) of an account forgets its tokens.

## IMAP client

PHP's ext-imap (c-client) cannot do `AUTHENTICATE XOAUTH2`, so OAuth accounts use
a small socket IMAP client (`src/AntispamBundle/Imap/`, no new dependency):

| Class | Role |
| --- | --- |
| `ImapClient` | IMAP4rev1 over `ssl://` / STARTTLS: CAPABILITY, `AUTHENTICATE XOAUTH2` (SASL-IR or continuation; the error challenge is answered with an empty line as SASL requires), LIST, CREATE, STATUS, SELECT, UID SEARCH / FETCH / STORE / COPY / MOVE, EXPUNGE / UID EXPUNGE, APPEND, LOGOUT. Literal-aware response parser; limits on line and literal size; nothing sent (token) ends up in messages. |
| `SocketConnection` | ddeboer `ConnectionInterface`. UID MOVE when the server has it (Gmail, Exchange Online), else COPY + `\Deleted`; `expunge()` removes only the messages this connection flagged when the server has UIDPLUS. |
| `SocketMailbox` | ddeboer `MailboxInterface`: STATUS like `imap_status()`, ddeboer search conditions passed to UID SEARCH, `n:*` sequences. |
| `SocketMessage` | ddeboer `MessageInterface`, loaded lazily with `BODY.PEEK` (never marks as seen): header + flags + INTERNALDATE + size first, the source (max 50 MB) when the body or attachments are needed; MIME decoded by `RawMessageParser`. |

`ImapScanService::connect()` returns this connection for OAuth accounts, so
`InboxService`, the message listeners, `QuarantineService`, `SpamFolderService`,
`RetroactiveSpamService`, `HealthService` and the account test need no change.
Password accounts keep the unchanged ext-imap path.

Encryption: SSL/TLS (port 993, default) or STARTTLS; "STARTTLS if available"
becomes required STARTTLS and "no encryption" is refused, so a token never goes
over plain text. With an empty host the provider's server is used
(`outlook.office365.com`, `imap.gmail.com`).

### Not supported for OAuth accounts

- The legacy single mailbox of *Konfiguracja (stara) → E-mail* (password only).
- *Sprawdź połączenie i certyfikat* on the account form (`/account/imap-check`)
  tests a c-client password login; for OAuth accounts use **Test** in the account
  list (real XOAUTH2 login, folder count).
- *Przywróć* of the legacy SPAM / QUARANTINE folder on `/spambox` (`spambox.restore`) - it only ever worked on the legacy mailbox.
- Plugin login with the mail password: OAuth accounts have no IMAP password on
  this server - set a **plugin password** on the account (see below).
- Google service accounts with domain-wide delegation; Microsoft device-code flow;
  certificate credentials (only client secrets) for app-only.
- Messages larger than 50 MB are not fetched for the body / attachment checks
  (they fail the pipeline for that UID like an unreadable message).
- IMAP SORT and THREAD are not used by the pipeline and not implemented.

### Mail client plugins

`/api/plugin/login` accepts the account's plugin password, and the IMAP password
only for password-login accounts. For an OAuth account the Microsoft / Google
password never works there; the edit page says so and the 401 answer carries a
Polish `message` (shown by the Thunderbird plugin 1.2.1+ and the Outlook add-in) that tells to
use the plugin password. The answer is the same for every failure, so it does not
reveal whether a mailbox exists or how it logs in.

## Setup: Microsoft 365 (Entra ID)

1. **Entra admin center** (entra.microsoft.com) → *Identity → Applications →
   App registrations → New registration*.
   - Name: e.g. `Antispam Pancernapanda`.
   - Supported account types: *Accounts in this organizational directory only*
     (one company) or *Accounts in any organizational directory* (MSP, several
     tenants; add *and personal Microsoft accounts* for Outlook.com).
   - Redirect URI: platform **Web**, `https://<your antispam>/account/oauth/callback`
     (copy it from *Ustawienia → Logowanie OAuth*).
2. *Certificates & secrets → Client secrets → New client secret*. Copy the
   **Value** (not the Secret ID). Note the expiry date - put a reminder in the
   calendar; an expired secret shows as `invalid_client` for every account.
3. *API permissions → Add a permission → Microsoft Graph → Delegated*:
   `offline_access`, `openid`, `email`, `profile`, `IMAP.AccessAsUser.All`.
   Optionally *Grant admin consent for <tenant>* so users do not see a consent
   prompt (required when user consent is disabled in the tenant).
4. Copy *Application (client) ID* and *Directory (tenant) ID* from *Overview*
   into *Ustawienia → Logowanie OAuth* with the secret. Tenant: the directory
   ID or a verified domain for a single-tenant app; empty (= `common`) or
   `organizations` for a multi-tenant app.
5. IMAP must be enabled for the mailbox: Microsoft 365 admin center → Users →
   the user → Mail → *Manage email apps* → **IMAP** on (or
   `Set-CASMailbox -Identity jan@firma.pl -ImapEnabled $true`).
6. Account in antispam: *Konta → Dodaj / Edytuj*, IMAP, *Sposób logowania* =
   *Microsoft 365 - OAuth (zgoda użytkownika)*, host empty (or
   `outlook.office365.com`), login = mailbox address (a shared mailbox address
   works if the consenting user has Full Access to it). Save, then **Połącz z
   Microsoft 365** and sign in as that user (or an admin with access).

### App-only (client credentials) - many mailboxes, no user sign-in

1. Same app; *API permissions → Add a permission → APIs my organization uses →
   Office 365 Exchange Online → Application permissions → IMAP.AccessAsApp*, then
   **Grant admin consent**.
2. Register the service principal in Exchange Online and grant mailbox access
   (Exchange Online PowerShell):
   ```powershell
   Install-Module -Name ExchangeOnlineManagement
   Connect-ExchangeOnline -Organization <tenantId>
   # AppId = Application (client) ID; ObjectId = Object ID of the ENTERPRISE APPLICATION
   # (Entra → Enterprise applications → the app → Overview), not of the app registration
   New-ServicePrincipal -AppId <APPLICATION_ID> -ObjectId <OBJECT_ID> -DisplayName "Antispam"
   Add-MailboxPermission -Identity "jan@firma.pl" -User <OBJECT_ID or service principal identity> -AccessRights FullAccess
   ```
   Repeat `Add-MailboxPermission` for every mailbox. The token gives access to
   exactly these mailboxes.
3. The tenant must be specific (GUID or domain): set it in
   *Ustawienia → Logowanie OAuth* or per account (*Tenant Microsoft*).
4. Account: *Sposób logowania* = *Microsoft 365 - OAuth aplikacji*, login = the
   mailbox address. No *Połącz* - use **Test** in the account list.

## Setup: Google (Gmail, Workspace)

1. console.cloud.google.com → new project → *APIs & Services → Library* →
   enable **Gmail API**.
2. *OAuth consent screen* (Google Auth Platform → Branding / Audience):
   - Workspace domain: user type **Internal** - only your users, no Google
     verification needed.
   - Gmail / several domains: **External**. In *Testing* status only listed test
     users can connect and **refresh tokens expire after 7 days**. Production use
     of the restricted `https://mail.google.com/` scope by an external app
     requires Google's verification (and a security assessment); for a few
     mailboxes keep Testing and reconnect, or use an app password with the
     password login instead.
   - Scopes (*Data access*): `https://mail.google.com/`, `openid`, `.../auth/userinfo.email`.
3. *Credentials → Create credentials → OAuth client ID* → **Web application** →
   *Authorized redirect URIs*: `https://<your antispam>/account/oauth/callback`.
   Copy client ID and secret into *Ustawienia → Logowanie OAuth*.
4. IMAP: Workspace admin console → Apps → Google Workspace → Gmail → *End User
   Access* → IMAP access on (personal Gmail: IMAP is always on now).
5. Account: *Sposób logowania* = *Google - OAuth*, host empty (`imap.gmail.com`),
   login = the Gmail address (or empty: the address you sign in with). Save →
   **Połącz z Google** → sign in with **that** Google account.

Gmail notes: folders are labels; `SPAM` and `QUARANTINE` are created as labels
(Gmail's own spam folder is `[Gmail]/Spam` and is not used). *Usuwaj spam*
flags + expunges the message in INBOX, which in Gmail by default only removes
the INBOX label (the message stays in *All Mail*) - prefer moving to SPAM, or
change Gmail's IMAP setting "When a message is marked as deleted and expunged".

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `AADSTS50011` redirect URI mismatch | The registered URI differs (http vs https, host, trailing slash). Copy it from *Logowanie OAuth*; set the public URL. Google: `redirect_uri_mismatch`, same fix. |
| `AADSTS65001` / `consent_required`, `access_denied` | Consent not given or user consent disabled: *Grant admin consent* in API permissions. |
| `AADSTS700016` | Wrong client ID or the app does not exist in that tenant (single-tenant app with tenant `common`): set the tenant ID. |
| `invalid_client` / `AADSTS7000215` | Wrong or expired client secret - create a new one and save it. |
| `invalid_grant` on refresh | Refresh token revoked or expired (password reset, user removed the app, Google Testing app after 7 days, 90 days of inactivity at Microsoft): **Połącz ponownie**. |
| `Logowanie OAuth2 (XOAUTH2) odrzucone ... AUTHENTICATE failed` (Microsoft) | IMAP disabled for the mailbox, wrong login (must be the mailbox / UPN), no Full Access to a shared mailbox, or for app-only: service principal / `Add-MailboxPermission` missing or the wrong Object ID used. |
| Same with `status=400` / `status=401` (Google) | The token is for another Google account than the login, or the scope was not granted; reconnect and tick the Gmail permission. |
| `Google nie zwrócił tokenu odświeżania` | Google issues a refresh token only on the first consent: remove the app at myaccount.google.com/permissions and connect again (antispam already sends `prompt=consent`). |
| `Logowanie aplikacji (client credentials) wymaga konkretnego tenanta` | Set the directory ID globally or on the account. |
| `nie można odszyfrować` | `APP_SECRET` changed: enter the client secrets again and reconnect the accounts. |
| `Nieprawidłowy lub wygasły parametr state` | The callback came > 15 minutes later, in another browser / session, or twice. Start again with *Połącz*. |

Logs: renewal failures are logged (`OAuth token refresh failed for account N`)
and visible in *Dziennik audytu* (`account.oauth_refresh_failed`).

## Data, backup, security

New nullable columns on `antispam_account`: `imap_auth_method`, `oauth_username`,
`oauth_tenant`, `oauth_access_token` (encrypted), `oauth_token_expires_at`,
`oauth_refresh_token` (encrypted), `oauth_connected_at`, `oauth_error`,
`oauth_error_at`. Existing accounts (`NULL`) keep the password login.

Backups (`antispam:export`, [backup.md](backup.md)): the login method and the
tenant are always exported; the client secrets (`oauth.*.client_secret`) and the
refresh tokens only with `--include-secrets`, encrypted with the instance key.
Access tokens are never exported (renewed on first use). An older backup without
`imap_auth_method` keeps the password login.

Audit ([audit.md](audit.md)): `account.oauth_connected`, `account.oauth_disconnected`,
`account.oauth_refresh_failed`, and `settings.save` with `target_id = oauth`
(secrets by name only). Tokens and secrets are never logged.

## Tests

`Tests/Imap/ImapClientTest.php` (scripted server: XOAUTH2 string = the Microsoft
documentation example, SASL-IR and continuation, Google error challenge,
literals, LIST / STATUS / SEARCH, MOVE vs COPY + UID EXPUNGE, injection guards),
`Tests/Imap/SocketAdapterIntegrationTest.php` (adapter + `ImapScanService::scan()`
against a real IMAP server; skipped unless `ANTISPAM_TEST_IMAP=host:port`, e.g.
GreenMail - see the class doc), `Tests/Services/OAuth/*` (authorize URL, PKCE,
code exchange, refresh, rotation, locking re-read, errors, client credentials,
with `MockHttpClient`), `Tests/Controller/OAuthControllerTest.php` (state /
PKCE in the session, forged / expired / replayed state, provider error, Google
account mismatch, CSRF, disconnect), `Tests/Controller/OAuthTemplatesAndAccessTest.php`
(ROLE_ADMIN, templates, form validation), plus backup, doctor, health and plugin
login cases.
