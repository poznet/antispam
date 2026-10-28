# Changelog

All notable changes to Antispam Pancernapanda are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The running version is shown in the panel footer (admins), in
`/api/plugin/status` (`server_version`) and by `bin/console --version`; the
single source is `AntispamBundle\AppVersion::VERSION`. How to cut a release:
`docs/deployment.md`, section *Releasing*.

Versions before 2.0.0 were never tagged: they were reconstructed from the git
history and group the commits of one development push each.

Mail client plugins and the SSH+Maildir agent have their own version numbers
(Thunderbird plugin `PluginApiController::PLUGIN_VERSION`, agent
`AGENT_VERSION` in `antispam-agent.php`); their bumps are listed here too.

## [Unreleased]

### Added
- Background job queue (**Przegląd → Zadania w tle**, `/jobs`): heavy panel actions
  no longer run inside the HTTP request (the first "Skanuj" of a big mailbox ended in
  `504 Gateway Timeout`). Queued: account **Skanuj**, **Wdróż**, **Synchronizuj**,
  **Stan**; the retroactive pass of a new blacklist rule (rule forms, Phishing →
  Zablokuj, plugin reports - replaces the `kernel.terminate` pass); user-area agent
  rule syncs; **Synchronizuj teraz** of the CERT list; **Wyślij teraz** of the
  quarantine digest; bulk phishing forward; the full health check. The button
  redirects to a job page with live progress and the same result view as before;
  dedupe (a second click returns the running job), cancel, "w kolejce / trwa" badges
  on the account list. Worker `antispam:jobs:work` (alias `antispam:jobs:run --once`
  for cron) runs continuously in the Docker `scheduler` (`JOBS_WORKER`,
  `JOBS_JOB_TIMEOUT`, `JOBS_BATCH_SECONDS`), recovers jobs of a dead worker, per-job
  time limit (image now has `pcntl`). Big first IMAP scans run in resumable batches
  (cursor after each batch, kept "initial" until finished); `scan-all` shares the
  per-mailbox lock, skips busy mailboxes instead of failing and gives each IMAP
  mailbox at most `SCAN_MAX_SECONDS` (600) per run. Health check / doctor `jobs`,
  `antispam_jobs_*` metrics, `antispam:purge` drops finished jobs after
  `jobs.retention_days` (30). New table `antispam_job` (migration
  `Version20261028201942`). See `docs/jobs.md`.
- Optional local learned classifier (naive Bayes, Robinson / chi-square,
  off by default; Ustawienia → Filtr spamu): learns from plugin spam / not-spam
  and phishing reports, quarantine and SPAM releases and
  `antispam:bayes:train`; scores in the IMAP pipeline (`CheckBayes`), the
  plugin check and the SSH agent 3.2 (token table synced with the rules).
  Hashed tokens only. New tables `antispam_bayes_token`,
  `antispam_bayes_message` (migration `Version20261028180826`). See `docs/bayes.md`.
- OAuth2 (SASL XOAUTH2) IMAP login for **Microsoft 365 / Outlook.com** (delegated
  authorization code + PKCE, or app-only client credentials) and **Gmail / Google
  Workspace** (authorization code + PKCE): *Sposób logowania* on the account form,
  **Połącz / Rozłącz** on the edit page, provider apps under **Ustawienia →
  Logowanie OAuth** (`/config/oauth/`), callback `/account/oauth/callback`.
  OAuth accounts use a new socket IMAP client (`src/AntispamBundle/Imap/`,
  ddeboer interfaces) - scan, quarantine / SPAM release, retroactive blacklist,
  test and health work as for password accounts; password accounts keep ext-imap.
  Tokens encrypted, renewed under a per-account lock; failures in the account
  list, Stan systemu, `antispam:doctor` (`oauth`) and the audit log
  (`account.oauth_*`). Backups carry the login method, and with secrets the
  client secrets and refresh tokens. New dependency `symfony/http-client`; new
  nullable columns on `antispam_account` (migration `Version20261028181522`). Thunderbird plugin
  1.2.1 / Outlook add-in show the server's login error message. See `docs/oauth.md`.
- Per-mailbox settings (**Konta → Edytuj → Ustawienia skrzynki**, empty =
  inherit the global value): spam / quarantine threshold, scoring on/off,
  quarantine digest on/off, digest recipient and send hour. Honoured by the
  IMAP scan, the SSH agent (scan flags and synced settings), the plugin
  check, the retroactive blacklist pass and the digest; badge on the account
  list, overrides in the `account.edit` audit entry and in backups.
  `antispam:digest:send --scheduled-only` (hourly in the Docker scheduler) and
  arguments after `--` for `antispam:cron:run`. New nullable columns on
  `antispam_account` (migration `Version20261028134625`).
- User self-service: own sender white/blacklists (`/my/rules`, exact + wildcard,
  owned by the user's mailboxes; SSH agents get the rules synced after the response),
  SPAM folder with "Przywróć do skrzynki" / "Przywróć i zawsze akceptuj" for IMAP and
  SSH mailboxes (`/my/spam`; the user menu "Spam" now points there).
- Two-factor authentication (TOTP, local QR code, hashed backup codes, throttled code
  step) for database users; `ADMIN_TOTP_SECRET` for the env admin; admin reset and
  "Wymagaj 2FA dla administratorów"; `antispam:2fa:secret`.
- Agent 3.1: `spam-list` / `spam-release` (redeploy SSH accounts: Konta → Wdróż).
- Distributable plugin builds (`docs/plugin-distribution.md`): generic Thunderbird
  `.xpi` without a server URL for addons.thunderbird.net (`/plugin/download?build=generic`,
  `bin/build-thunderbird-xpi`, `antispam:plugin:build`; reproducible), upload of the
  reviewed package in *Wtyczki pocztowe* (validated: add-on id, version, no baked-in
  server; `/plugin/download` serves it while current), self-hosted updates of the
  instance build (`update_url`, `/plugin/thunderbird/updates.json`, https only), public
  setup page `/plugin/setup`, GitHub workflow `thunderbird-plugin.yml` (build, lint,
  optional ATN submission with `ATN_API_KEY` / `ATN_API_SECRET`), Apple Mail
  `scripts/build-and-notarize.sh` (Developer ID + notarytool).
- Thunderbird plugin 1.2.0 (1.2.1 with the OAuth login message): first-run setup when the package has no server address
  (settings open on install, *Pierwsze uruchomienie* box, pasted setup / panel links are
  cut to the base URL), connection test shows the build kind. Apple Mail app: same URL
  normalisation.
- Audit actions `spam.release`, `spam.whitelist`, `auth.2fa_*`.
- New nullable 2FA columns on `antispam_user` (migration `Version20261028135851`).

### Changed
- Database schema is versioned with Doctrine Migrations (`migrations/`, baseline =
  full 2.0.0 schema). The Docker entrypoint runs the new `antispam:db:upgrade` instead
  of `doctrine:schema:update --force`: fresh database -> all migrations; install made
  by `schema:update` -> one last `schema:update` (never drops unknown tables), baseline
  recorded as executed; migrated -> pending migrations only. `--dry-run`, MySQL named
  lock against concurrent boots, exit 2 when an entity change has no migration.
  `RUN_MIGRATIONS_STRICT=true` stops the container when the upgrade fails (default:
  loud error, start anyway). `antispam:doctor` `schema` now fails on pending
  migrations and warns on entity changes without a migration. See `docs/migrations.md`.

## [2.0.0] - 2026-10-28 (current)

Major version: several user and operator visible behaviours changed (multiple
users and roles, rule ownership with global `*` rules, new IMAP marker format,
agent protocol 3.0, conservative header scoring).

### Added
- Release hygiene: application version (`AppVersion`, container parameter
  `antispam.version`, Twig global `antispam_version`), build commit written to
  `REVISION` from the Docker build arg `GIT_COMMIT` (Coolify `SOURCE_COMMIT`),
  version + commit in the panel footer for admins, *Co nowego* page
  (`/changelog`) rendering this file, `server_version` in
  `/api/plugin/status`, app name and version in `bin/console --version`.
- Multiple users with `ROLE_ADMIN` and `ROLE_USER`: end users see only their
  own mailboxes (quarantine, spam, score log) under `/my`, `/start` sends each
  role to its landing page, password change for database users.
- Rule ownership: white/blacklist rules belong to one mailbox or to all of
  them (owner `*`), owner filter and selector on the rule lists, CSRF on bulk
  import, `antispam:rules:make-global` to turn legacy mailbox rules into global
  ones.
- Phishing reports from the mail client plugins: full message storage,
  `/phishing` analysis page, blocking the sender, `.eml` export; CERT-listed
  domains flagged in the analysis.
- CERT Polska domain list filter (hole.cert.pl) in the scoring pipeline and in
  the agent.
- Branded error pages (403, 404, 500 and the rest).
- Self-hosted web fonts (Montserrat, Open Sans) instead of Google Fonts.
- Thunderbird plugin 1.1.1: messages are filed locally first, separate click
  queue, request timeouts.
- Thunderbird plugin 1.1.2: preferences tab, reports from the junk button,
  deferred retroactive pass after a report.
- Outlook add-in and Apple Mail (MailKit) extension source.
- Spam moved per mailbox, retroactive blacklist pass, IMAP accounts in cron and
  quarantine, cron run log (`antispam:cron:run`, `/cron/logs`).
- Decision source and outcome recorded in the score log; the quarantine page
  shows where quarantined mail is now.
- ClamAV container in the compose stacks.

### Changed
- Home page repositioned as an on-premise antispam for companies.
- The first scan of a new mailbox is kept out of the statistics and the
  dashboard.
- Header scoring is conservative: only the topmost Authentication-Results
  counts, `dkim=none` / `dmarc=none` are 1 point each, soft signals are capped
  below the quarantine threshold and all headers below the spam threshold.
- IMAP scan (review batches 1-2): markers keyed per mailbox + Message-ID, INBOX
  read incrementally from a UID cursor, c-client timeouts, per-mailbox locks,
  failed messages retried.
- Retroactive pass: 30-day window for every rule, newest first, per-message
  errors instead of aborting the pass.
- SSH+Maildir agent 3.0 (review batch 5): From: addr-spec as the sender,
  thresholds and switches synced from the panel, verified Maildir moves, clean
  JSON protocol, per-account rules database, PatternMatcher / header / DNSBL
  parity with the web side; panel pins the SSH host key (TOFU), detects old
  agents and timeouts.
- UI polish (review batch 6): responsive tables, theme-token KPI tiles,
  CSP-safe JavaScript (`data-confirm`), one wording for releasing mail
  (*Przywróć*).
- Documentation menu paths match the panel; stale DNSBL and parity claims
  fixed.

### Fixed
- Review batch 3 (web security): CSRF tokens and POST-only state changes,
  login throttling, security headers, secrets handling.
- Review batches 1-2 (scoring): IMAP mailboxes now get SPF/DKIM/DMARC, own-domain
  spoofing and DNSBL checks (raw headers instead of `imap_headerinfo()`),
  DNSBL answers outside 127/8 ignored and not cached, ReDoS-safe regex rules.
- Review batch 4: quarantine digest, quarantine, shared feed and schema fixes.
- Cross-batch gaps: restored messages are marked checked so they are not
  filtered again, interactive IMAP tests use the scan timeouts, rule forms and
  bulk import refuse invalid regexes.
- Security review findings in the mail plugins and phishing reports.
- 500 on the quarantine digest page for IMAP account mailboxes.
- Every role can log out (`/logout` public in `access_control`).
- PHPUnit bootstrap loads `.env`, so kernel tests pass from a cold cache.

## [1.4.0] - 2026-10-27

### Added
- Thunderbird plugin: spam / not-spam reports and on-arrival checks
  (`/api/plugin`).
- Impersonation / BEC detection, link protection, attachment policy and the
  end-user quarantine digest e-mail with signed `/q/` links.
- Landing page served as the home page with the login form embedded.
- `docker-compose.prod.yml` for Coolify with a scheduler service.
- Clickable SSL/TLS options and a connection check in the IMAP account form.
- Filters and pagination in the score log (*Dziennik ocen*); every mailbox's
  quarantine on the quarantine page.

### Changed
- Migrated to Symfony 7.4 LTS on PHP 8.2 (Doctrine ORM 3 / DBAL 4), dead
  dependencies dropped; Docker image on PHP 8.2 / Debian bookworm.
- Admin panel redesigned (sidebar layout, dark mode) and translated to Polish.
- Rebranded to "Antispam Pancernapanda".

### Fixed
- Thunderbird plugin talking to `http://` behind a proxy; plugin reports are
  logged.
- Security fixes ported to the Symfony 7.4 code.

## [1.3.0] - 2026-06-05

### Added
- ClamAV attachment scanning in the spam pipeline and in the Maildir agent.
- VirusTotal attachment lookup and ClamAV / VirusTotal settings.
- Shared spam feed (centralized spam database) with an HTTP API and a sync
  command.

### Changed
- N+1 queries removed from the scan pipeline and the counter reset.

## [1.2.0] - 2026-04-16

### Added
- Dockerfile and docker-compose stack for Coolify deployment.
- Login required for the web UI.
- Spam scoring pipeline, DNSBL integration, quarantine and analytics.

### Changed
- UI rebranded to Pancernapanda antispam.

## [1.1.0] - 2026-03-09

### Added
- Multiple mail accounts and the SSH+Maildir agent mode.

### Changed
- UI: dashboard, navbar, list views and form styling.

## [1.0.0] - 2025-10-21

### Changed
- Upgraded from Symfony 2.8 to Symfony 4.4 LTS.

### Fixed
- Critical bugs and error handling.

## [0.1.0] - 2016-07-03

### Added
- First release: IMAP mailbox check driven by an event pipeline, domain and
  e-mail white/blacklists with a web UI, "already checked" markers, move to
  the spam folder, spam counter reset, configuration screen.
