# Phishing reports

Users logged in to a mail client plugin can mark a message as a **phishing
attempt** ("Zgłoś próbę wyłudzenia / phishing"). Unlike a spam report, the
whole message is kept so the admin can inspect it, build filters from it and
forward it (e.g. to CERT Polska).

## Flow

1. Thunderbird (context menu) or Outlook (task pane button) sends the full
   RFC 822 source to `POST /api/plugin/phishing` - attachments included, up to
   `max_upload_bytes` from `/api/plugin/status` (setting `plugin.max_upload_kb`,
   default 700 KiB to fit a 1 MiB proxy body limit; at most 10 MiB,
   `PhishingReportService::MAX_RAW_BYTES`). Bigger messages are cut and
   flagged as `truncated` (also Outlook clients older than Mailbox 1.14,
   which can only rebuild headers + text body). Login is required (the content is stored); the
   Apple Mail extension has no per-message action in MailKit, so it cannot
   report phishing.
2. The server stores a `PhishingReport` (table `antispam_phishing_report`,
   raw source in a blob) and also handles it as a spam report:
   `PluginService::learn()` puts the sender on the account's e-mail blacklist,
   records shared-feed fingerprints and the retroactive pass moves that
   sender's INBOX mail to SPAM (a background job, [jobs.md](jobs.md)).
3. The same message reported again by the same account (same SHA-256) only
   increments `report_count`.
   **From another Thunderbird account** (plugin 1.3.0+): when the message is in
   a Thunderbird account that has no login of its own and the plugin is set to
   *zgłaszaj tylko do administratora* (default), the request is authenticated
   with another account's login and carries `"scope": "report_only"` and
   `reported_from` (that account's addresses). The report is stored with
   `reported_from` and `report_only = 1`, shared fingerprints are recorded,
   but step 2's blacklist rule, Bayes training and retroactive pass are
   **skipped** - the authenticating mailbox (`account_email`) only vouches for
   the request. The list shows *z konta: … (tylko zgłoszenie)* under the
   mailbox, the detail page explains it and warns that **Filtrowanie** rules
   would go to the authenticating mailbox. In the plugin's *traktuj jak
   podpiętą skrzynkę* mode the report is learned as before and
   `reported_from` is stored for information only. Requests without `scope`
   (older plugins, Outlook) behave as before.
4. The client files the message as junk, like a spam report (Outlook cannot
   move mail; it shows the junk hint instead).

Rate limit: 30 reports per account per hour (`phishing` bucket). Storage
quota: 500 MiB of stored sources per mailbox and 5 GiB in total
(`PhishingReportService::MAX_STORED_BYTES_PER_ACCOUNT` / `_TOTAL`); over it
the API answers `507` until the admin deletes older reports (also possible
straight from the list). A phishing report also counts against the account's
spam-report limit, since it is learned as spam too.

Hostile input: sender / subject fields are scrubbed to valid UTF-8 before
they are stored, and the parser stops after 500 MIME parts and 2000 header
lines, so a crafted message cannot make its own analysis page fail.
Retention: reports not re-reported for 365 days are purged when a new one
arrives.

## Panel: Skrzynki → Zgłoszenia phishingu (`/phishing`)

- **List**: filter by status, mailbox, sender / Reply-To / subject substring.
  The raw source is never loaded for the list.
- **Detail** (`/phishing/{id}`), computed on the fly by
  `PhishingReportService::analyze()` from the stored source:
  - sender, Reply-To, Return-Path, connecting IP, mailer;
  - SPF / DKIM / DMARC from `Authentication-Results` (topmost first) /
    `Received-SPF`, DKIM signing domains;
  - **red flags**: auth failures, DKIM domain unrelated to From, Reply-To or
    Return-Path in another domain, display name pretending to be another
    address, links whose visible text shows a different domain than the
    target, links to IP addresses, risky attachment extensions, truncation,
    and sender / link domains on the CERT Polska list (see
    [protection.md](protection.md); shown whenever the list has been synced,
    even with the CERT filter off - listed link domains are highlighted);
  - links (not clickable) with per-domain counts linking to VirusTotal;
  - attachments with type, size and SHA-256 (VirusTotal link);
  - text body, HTML **source** (escaped, never rendered) and all decoded
    headers.
- **Status**: `nowe`, `potwierdzony phishing`, `zgłoszone do CERT`,
  `to nie phishing`, plus a free-text note (e.g. the CERT case number).
- **Filtering** for the reporting mailbox: block the sender address or the
  whole sender domain (not offered for free-mail domains such as gmail.com or
  wp.pl). Rules get the spam threshold as their score and are applied
  retroactively (30 days of INBOX → SPAM).
- **Download .eml** (`message/rfc822`, attachment, sandbox CSP) - the format
  CERT Polska accepts; the page links to https://incydent.cert.pl.
- **Wyślij do CERT Polska** - one-click forward by e-mail, see below. The list
  shows a "wysłano" / "błąd wysyłki" badge and has a bulk action for the
  selected reports.
- **Delete** removes the report with its content.

## Forwarding to CERT Polska / SOC

`PhishingForwardService`, actions `POST /phishing/{id}/forward`
(`antispam_phishing_forward`), `POST /phishing/forward` (bulk,
`antispam_phishing_forward_bulk`) and the settings page
`/phishing/forward-settings` (`antispam_phishing_forward_settings`, linked
from the list and the detail page). All are ROLE_ADMIN, POST + CSRF and the
buttons ask for confirmation (`data-confirm`).

**Recipient.** Default `cert@cert.pl` - CERT Polska's incident address: "The
preferred method for contacting CERT Polska is via e-mail at <cert@cert.pl>"
(RFC 2350 of the team, version 2.1 of 13 March 2025,
https://cert.pl/en/uploads/misc/rfc2350.txt; the same address is listed under
"Zgłaszanie incydentów" on https://cert.pl/kontakt/). The web form
https://incydent.cert.pl/ (category "Podejrzana wiadomość e-mail", attach the
downloaded .eml) stays linked as the alternative. SMS phishing goes to 8080,
not by e-mail. The default applies only while the setting was never saved;
clearing the field disables forwarding. Up to 5 recipients (e.g. a SOC
address instead of / next to CERT).

**The e-mail.**
- From: *Adres nadawcy* of these settings, falling back to the quarantine
  digest sender (`digest.from_email`); sent through `MAILER_DSN`. CERT replies
  with a case number to that address - optionally CC the admin.
- Subject: `Phishing: <original subject>` (folded to one line, 200 chars).
- Text: the note template (`{id}`, `{subject}`, `{sender}`; default a short
  Polish intro) followed by the analysis summary: sender, Reply-To,
  Return-Path, subject, date, connecting IP, SPF/DKIM/DMARC, link domains,
  SHA-256 and the red flags.
- Attachment: the stored source **unmodified** as `message/rfc822`, encoded
  `8bit` (RFC 2046 forbids base64 for message/rfc822); only a source with NUL
  bytes or lines over 998 octets falls back to base64 (decoded content is
  still byte-identical).
- **Privacy:** the reporting mailbox address is *not* written into the note
  unless *Podaj adres skrzynki* is checked (default off). The original headers
  (To, Received) usually still contain it - that is the evidence CERT needs.
- **Size limit** (default 10240 KiB, 64-25600): a bigger source is not cut
  (that would corrupt it) - only its headers are attached as
  `text/rfc822-headers` (capped at 256 KiB) and the note says so. A report the
  plugin already truncated (`truncated`) is sent as is with a notice that
  parts / attachments may be missing.

**Recorded on the report** (nullable columns, part of the baseline migration):
`forwarded_at`, `forwarded_to` (To + Cc), `forward_error` (last failure,
cleared on success), `forward_attempted_at`. On success the status moves from
`nowe` / `potwierdzony phishing` to `zgłoszone do CERT`.

**Double-send guard.**
- A report already forwarded - or another report of the same message (same
  SHA-256, e.g. reported by a second mailbox) - is refused unless the form
  sends `resend=1`; the detail page then shows "Wyślij ponownie" with a second
  confirmation naming the earlier date and recipients.
- Each attempt first claims the row with an atomic `UPDATE ... WHERE`
  (`PhishingReportRepository::claimForForward`), so a double click or a
  parallel cron run cannot send twice. A claim that neither succeeded nor
  failed expires after 10 minutes; a failed attempt can be retried at once.
- Bulk forwarding never resends: already sent reports, copies of a message
  sent in the same batch and `to nie phishing` reports are skipped (their
  checkboxes are disabled on the list). False positives are never sent.

**Automatic mode** (off by default, *Wysyłaj automatycznie po N min*):
`antispam:phishing:forward`, run by the scheduler every
`PHISHING_FORWARD_INTERVAL` minutes (default 10, `0` = off), forwards reports
with status `nowe` / `potwierdzony phishing` that are older than N minutes,
so the admin has N minutes to mark a report as `to nie phishing`. Safety
limits: only reports received **after** the mode was switched on
(`phishing_forward.auto_since` - the backlog is never mass-sent), at most 20
per run, one e-mail per message (copies are skipped), each report is tried
once (a failure stays visible on the report, retry by hand).

Settings (`config` table): `phishing_forward.recipients`, `.cc`,
`.from_email`, `.from_name`, `.note`, `.include_reporter`, `.max_kb`,
`.auto_minutes`, `.auto_since`.
