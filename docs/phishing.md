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
   sender's INBOX mail to SPAM (after the response has been sent).
3. The same message reported again by the same account (same SHA-256) only
   increments `report_count`.
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
- **Delete** removes the report with its content.

Sending reports to CERT automatically is not implemented yet.
