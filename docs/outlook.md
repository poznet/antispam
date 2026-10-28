# Outlook add-in

An Office (Outlook) add-in with a task pane that talks to the same
`/api/plugin/*` endpoints as the Thunderbird plugin ([thunderbird.md](thunderbird.md)).
Source: `src/AntispamBundle/Resources/outlook/`. Server side:
`MailClientPluginController`, `MailClientPluginBuilder` (plus everything the
Thunderbird API uses).

## Supported clients

Office add-ins (XML manifest, `MailApp`, Mailbox requirement set 1.1, ribbon
button 1.5) run in:

- **new Outlook for Windows** and **Outlook on the web** (Microsoft 365, Outlook.com),
- **classic Outlook for Windows** (Microsoft 365 / Outlook 2021+; older builds that
  render add-ins with Internet Explorer get a "use a newer Outlook" message),
- **Outlook for Mac** (new and legacy UI).

Mobile Outlook is not declared in the manifest (no `MobileFormFactor`).

## Hosting

Office loads the add-in from URLs in the manifest, so the app hosts it itself:

| URL | |
|---|---|
| `/plugin/outlook/manifest.xml` | the manifest (download), server URL filled in |
| `/plugin/outlook/taskpane.html` (+ `.js`, `.css`) | the task pane |
| `/plugin/outlook/commands.html` | empty function file required by the manifest |
| `/plugin/outlook/icons/icon-{16,32,64,80,128}.png` | icons |

All are public (`security.yaml`) and only served when `plugin.enabled` is on.
The task pane runs on the antispam origin, so API calls are **same-origin** — no
CORS configuration is needed. The app does not send `X-Frame-Options` /
`frame-ancestors`, which matters because Outlook on the web shows the pane in an
iframe; keep it that way for `/plugin/outlook/*` if a proxy adds such headers.

**HTTPS is mandatory** (Office refuses `http://` add-ins, except `localhost`).
The manifest URL comes from **Publiczny adres** (`plugin.public_url`) or the
request; if it resolves to `http://…`, `/plugin/outlook/manifest.xml` returns
`409` with an explanation and the panel shows a warning instead of the button.
Set `plugin.public_url` or `SYMFONY_TRUSTED_PROXIES` behind a TLS proxy.

The manifest has a fixed add-in `Id` (GUID). One instance = one add-in; if two
antispam instances are deployed for the same Microsoft 365 tenant, change the
`Id` in `Resources/outlook/manifest.xml` for one of them.

## Installing

- **User (sideload):** download *antispam-outlook.xml* (home page, Thunderbird /
  Outlook section, or *Konfiguracja → Wtyczki pocztowe*). In Outlook: *Get
  Add-ins* (*Pobierz dodatki*) → *My add-ins* → *Custom add-ins* → *Add a custom
  add-in* → *Add from file…*. On the web the same dialog is at
  <https://aka.ms/olksideload>. Sideloading must be allowed by the tenant
  (default for most Microsoft 365 tenants; Outlook.com allows it).
- **Admin (whole organisation):** Microsoft 365 admin center → *Settings →
  Integrated apps → Upload custom apps* → *Office Add-in* → upload the manifest
  file (or give its URL). Deployment to users can take up to 24 h.

The add-in appears as an **Antyspam** button on the ribbon / message toolbar
when a message is open (read mode).

## What it does

| | Not logged in | Logged in |
|---|---|---|
| Zgłoś spam (shared spam DB) | ✔ (if `plugin.anonymous_reports`) | ✔ + sender on the account's e-mail blacklist |
| To nie spam | — | ✔ sender whitelisted |
| Sprawdź w Antyspamie | — | ✔ shows decision, score, reasons |
| Check opened messages automatically | — | ✔ optional, while the pane is **pinned** |
| Zgłoś phishing | — | ✔ whole `.eml` (up to 10 MiB) to *Zgłoszenia phishingu*, sender blacklisted ([phishing.md](phishing.md)) |

Login uses the same credentials as Thunderbird: mailbox e-mail + plugin
password (account form) or IMAP password. The token is stored in the add-in's
**roaming settings** (follows the mailbox to other Outlook clients) with
`localStorage` as a fallback.

Message source sent to the server:

- Mailbox 1.14+ (new Outlook, web, current Microsoft 365 desktop, Mac):
  `item.getAsFileAsync()` → the real `.eml`, truncated to 700 KiB like Thunderbird
  (or `max_upload_bytes` from `/api/plugin/status` when lower; phishing reports
  up to `max_upload_bytes`, resent cut to 700 KiB if a proxy answers `413`);
- older clients: internet headers (`getAllInternetHeadersAsync`, 1.8) + the plain
  text body, relabelled as `text/plain`; without 1.8 only From / Subject / Date /
  Message-ID are synthesised. Scoring is then less precise (no HTML / attachment
  analysis).

Results are also shown as a short notification bar on the message
(`notificationMessages`).

## Limitations (compared to Thunderbird)

- **No on-arrival checks.** Outlook event-based activation only covers compose
  events (`OnNewMessageCompose`, `OnMessageSend`, …) and attachment / header
  triggered read events in preview; there is no "new mail received" event for
  add-ins. New mail is filtered server-side (IMAP scan / Maildir agent) anyway.
  The closest equivalent is the "check opened messages automatically" option of
  the pinned task pane.
- **No moving to Junk.** Office.js cannot move an item in read mode; that would
  need Microsoft Graph (Azure app registration, SSO consent). The pane shows the
  decision and asks the user to use Outlook's own *Junk* / *Report* button.
- **Outlook's Junk button is not hooked.** Unlike Thunderbird, marking a message
  as junk with Outlook's own button does not report it to antispam.
- Reports are logged as plugin reports (*Skrzynki → Zgłoszenia z wtyczki*) like
  Thunderbird ones; checks are logged with `source:thunderbird_plugin` (the API is
  shared and does not distinguish clients).

## Not verified here

The manifest was checked for well-formedness and against the URLs the app
serves (unit test), not with Microsoft's validator
(`npx office-addin-manifest validate antispam-outlook.xml`) or a real Outlook.
Run the validator and a sideload test before rolling it out.
