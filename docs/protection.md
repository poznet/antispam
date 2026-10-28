# Advanced Protection

Three scoring steps inspired by Barracuda Email Protection. They need no external
daemon (Safe Browsing and URI block lists are optional), run in both the web
pipeline (IMAP) and the Maildir agent (SSH), and are configured under
**Ustawienia → Filtr spamu**. Each adds points to the message score like any
other signal (see [scoring.md](scoring.md)); none forces a decision on its own.

| Step | Web listener | Priority | Agent flag to disable |
|------|--------------|----------|------------------------|
| Impersonation / BEC | `CheckImpersonation` | 99988 | `--no-impersonation` |
| Link protection | `CheckUrls` | 99979 | `--no-urls` |
| Attachment policy | `CheckAttachmentPolicy` | 99976 | `--no-attachment-policy` |

All three are **on by default**. Pure logic lives in
`Services/ImpersonationAnalyzer`, `Services/UrlAnalyzer` and
`Services/AttachmentPolicyAnalyzer`; the agent carries a copy of the same rules
(`AgentParityTest` runs the same sample messages through both and compares
the results; it covers only these three analyzers, not header checks, lists or
DNSBL).

## Impersonation protection (BEC)

Targets CEO fraud and invoice scams, which often pass SPF/DKIM because they come
from real, freshly registered domains or free-mail accounts.

| Rule (score log) | Default | Fires when |
|------------------|---------|------------|
| `impersonation_vip:<name>` | 8 | Display name matches a protected person, but the address isn't one of theirs |
| `impersonation_display_address:<addr>` | 8 (VIP score) | Display name contains an address on a protected domain, sent from elsewhere |
| `display_name_embedded_address` | 3 | Display name contains a different e-mail address |
| `lookalike_domain:<from>~<protected>` | 6 | Sender domain imitates a protected domain |
| `internal_domain_spoof:<domain>` | 6 | From claims a protected domain and SPF or DMARC explicitly **failed** |

**Protected domains** = the configured list plus, unless switched off, each
account's own domain. Free-mail domains (gmail.com, wp.pl, onet.pl, interia.pl, …)
are never auto-protected, since their operators run sibling domains (interia.pl /
interia.eu).

**Protected people (VIPs)**, one per line:

```
Jan Kowalski <jan.kowalski@firma.pl>, jan@firma.pl
Anna Nowak
```

With addresses, only those addresses are legitimate for that name. Without an
address, any address on a protected domain is legitimate. Names are matched without
case or diacritics and in either order ("Kowalski Jan (Prezes)" matches). Single-word
names are ignored because they would match too much mail.

**Lookalike detection** (`match` in the reason says which rule hit), for protected
`firma.pl`:

| match | Example |
|-------|---------|
| `subdomain` | `firma.pl.evil.com` |
| `tld` | `firma.com`, `firma.eu` |
| `homoglyph` | `f1rma.pl`, `firrna.pl` (rn→m), `fırma.pl` / Cyrillic `fіrmа.pl` (punycode `xn--…`) |
| `affix` | `firma-pl.com`, `secure-firma.net`, `firma24.pl` |
| `typo` | `frima.pl`, `firmq.pl` (1 edit for names of 5–9 chars, 2 for 10+; a swap counts as 1) |

Names shorter than 4 characters are never compared. A company that legitimately
sends from several domains should list all of them as protected.

## Link protection

Links are extracted from the HTML and text body (first 1 MiB of each). Each rule
counts **once per message**, so a newsletter with 50 links can't stack points.

| Rule | Default | Fires when |
|------|---------|------------|
| `url_text_mismatch:<shown>-><real>` | 3 | Link text shows a domain (`www.pkobp.pl`) but the link goes to another one |
| `url_ip_host:<ip>` | 3 | Link points at a raw IP address |
| `url_shortener:<domain>` | 2 | bit.ly, tinyurl.com, t.co, cutt.ly, … |
| `url_punycode:<host>` | 3 | IDN host (`xn--…`), the usual vehicle for homograph phishing |
| `url_dbl:<zone>` | per zone (6) | A link's domain is on a URI block list |
| `url_safebrowsing` | 10 | Google Safe Browsing reports a link (optional) |

**URI block lists** (`zone score` per line; default `dbl.spamhaus.org 6` and
`multi.surbl.org 6`) are queried as `<registrable-domain>.<zone>`, for at most
*Max domains per message* (20) domains. Answers `127.0.0.1` (URIBL "query refused")
and `127.255.255.x` (Spamhaus error codes, e.g. when using a public resolver) are
**not** treated as listings. Spamhaus and URIBL block queries from big public
resolvers (8.8.8.8, 1.1.1.1); use a local caching resolver (unbound) for reliable
results. The agent caches answers for 1 h in `dnsbl_cache`.

**Google Safe Browsing** (v4 Lookup API) is off by default and needs an API key
from a Google Cloud project with the Safe Browsing API enabled. Up to 50 full URLs
per message are sent to Google. Errors and timeouts count as "no opinion".

Click-tracking redirects in legitimate newsletters can trigger the mismatch rule;
its default score (3) stays below the quarantine threshold on its own.

## Attachment policy

Rules on file names and raw bytes, with no ClamAV or API needed. Runs before the
ClamAV / VirusTotal steps. Each rule counts once per message.

| Rule | Default | Fires when |
|------|---------|------------|
| `attachment_blocked:<ext>` | 15 | Extension is on the blocked list |
| `attachment_double_extension` | 8 | `faktura.pdf.exe`, `skan.pdf      .scr` |
| `attachment_bidi_filename` | 8 (same score) | Unicode bidi override in the name (`faktura` + U+202E + `fdp.exe` shows as `fakturaexe.pdf`) |
| `attachment_disguised_executable:pe\|elf` | 10 | Windows PE / Linux ELF content under a non-executable name |
| `attachment_archive_blocked:<ext>` | 15 (blocked score) | A ZIP contains a file with a blocked extension |
| `attachment_office_macro` | 6 | OOXML with `vbaProject.bin` (docm/xlsm, or renamed to .docx) or legacy OLE with a VBA project |
| `attachment_pdf_active:<javascript\|js\|launch>` | 6 (macro score) | PDF with JavaScript or a Launch action |
| `attachment_encrypted_archive` | 5 | Password-protected ZIP: opaque to every scanner |
| `attachment_encrypted_office` | 5 (encrypted score) | Password-protected Office document |

Default blocked extensions:
`exe, scr, pif, com, bat, cmd, vbs, vbe, js, jse, wsf, wsh, hta, msi, msp, cpl, jar,
ps1, psm1, lnk, iso, img, vhd, vhdx, reg, scf, chm, dll, appx, msix, xll, url, inf,
sct, gadget`.

File names are decoded first (RFC 2047 / RFC 2231) and stripped of the trailing
dots and spaces Windows ignores (`setup.exe. ` → `setup.exe`). At most 25 MiB of
each attachment is inspected. ZIP archives are read from their local file headers
only and never extracted.

A blocked type (15) exceeds the default spam threshold (10) on its own. Set a score
to 0 to disable a single rule.

## CERT Polska warning list (`cert_hole`)

CERT Polska publishes the "Lista Ostrzeżeń" ([hole.cert.pl](https://hole.cert.pl)), the
phishing / malware domains that Polish ISPs block. A message scores when its sender
domain (From, Reply-To or Return-Path) or the host of any link in the body (HTML
`href` and plain-text URLs, via `UrlAnalyzer::extractLinks`) equals a listed domain
**or is a subdomain of one** (`a.b.evil.pl` is checked as `a.b.evil.pl`, `b.evil.pl`,
`evil.pl`). Reason rule: `cert_hole:<matched listed domain>`; the quarantine digest shows
it as "Domena z Listy Ostrzeżeń CERT Polska (phishing)" and treats it as high-risk
(no "always accept this sender"). Whitelisted senders skip the check.

- **Off by default.** Enable it, set the score (empty = spam threshold, so one hit is
  enough) and sync manually under **Blacklisty → Lista CERT** (`/cert/`).
- **Source:** `https://hole.cert.pl/domains/v2/domains.txt`, plain text, one domain per
  line, ~125k domains / ~2.5 MB, refreshed by CERT continuously. HTTPS only, 120 s
  timeout, 50 MB cap.
- **Storage:** table `antispam_cert_domain` (primary key = domain, lower-case punycode),
  replaced in one transaction with batched multi-row `INSERT`s. Status (last sync,
  count, last error) is in the `config` table (`cert.last_sync_at`, `cert.last_count`,
  `cert.last_error`).
- **Sanity check:** the table is only replaced when the download has at least 100 valid
  domains and at least 50% of the current count; otherwise the old list is kept and the
  error is recorded.
- **Normalization:** trim, lower-case, strip `*.` and trailing dot, IDN to punycode
  (`intl`), drop IPs, single labels, comments and invalid characters.
- **Web pipeline:** listener `CheckCertHole` (priority 99977, before `ApplyScoreDecision`)
  and `RawMessageScanner` (plugin checks) use `Services/CertHoleService`.
- **Scheduler:** `antispam:cert:sync` runs every `CERT_SYNC_INTERVAL` hours (default 6)
  and exits immediately while the filter is disabled.
- **SSH Maildir agents:** supported without pushing the list. The list is far too large
  for `syncRules` (argv / SSH command limits), so only the settings `cert_enabled` and
  `cert_score` are pushed (in `settings`). With the filter enabled, the agent downloads
  `domains.txt` itself at the start of a scan when its copy is older than 24 h (a failed
  attempt is retried after 1 h; the old list stays on any error) into the SQLite tables
  `cert_domains` / `cert_meta`, applying the same sanity check. The agent host therefore
  needs outbound HTTPS to hole.cert.pl and the `curl` extension; without them the check
  is simply a no-op. Disable per run with `--no-cert`.

## Settings storage

Scores and switches live in the `config` table (`impersonation.*`, `url.*`,
`attachment.*`). The list-shaped settings (protected domains, VIPs, URI block list
zones, blocked extensions) can exceed the config table's 255-character limit, so they
are stored in the `antispam_list_setting` table:

```sql
CREATE TABLE antispam_list_setting (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL UNIQUE,
    value LONGTEXT DEFAULT NULL
);
```

It is part of the baseline migration; `bin/console antispam:db:upgrade` creates it
(Docker does this at boot when `RUN_MIGRATIONS=true`, see [migrations.md](migrations.md)).
Until the table exists the defaults are used.

All settings are pushed to agents in the `settings` section of `import-rules`, so
**re-sync each SSH account** (Accounts → Sync or `antispam:agent:sync`) after
changing them. See [agent.md](agent.md).
