# Plugin distribution (signed / store builds)

How the mail client plugins get to users beyond "download from this
instance": a store listing, central deployment, a signed app. Each plugin
has the same problem: **the server URL is per instance**, but a store or
signed package must be one fixed file. The solution in every client is the
same: the shared package carries **no** server URL and asks for it on first
run; the per-instance download stays available for the zero-typing case.

| | Per-instance download (unchanged) | Shared package (new) |
|---|---|---|
| Thunderbird | `/plugin/download?build=instance` - URL in `config.json`, self-hosted auto-updates | generic `.xpi` for addons.thunderbird.net (ATN); the uploaded file is served by `/plugin/download` |
| Outlook | manifest from `/plugin/outlook/manifest.xml` (URLs of this instance) | not built - see [AppSource](#outlook-appsource) for the options |
| Apple Mail | source zip with the URL baked in | one Developer ID signed + notarized app built from the repository, URL entered in the app |

The setup page **`/plugin/setup`** (public, linked from *Ustawienia → Wtyczki
pocztowe*) shows the server address with a copy button and install steps. The
Thunderbird plugin and the Apple Mail app accept the whole setup link (or a
bare host, a panel or download link) and cut it to the base URL.

## Facts this design relies on (verified 2026-10-28)

- **Thunderbird does not verify add-on signatures.** Thunderbird is built with
  `MOZ_REQUIRE_SIGNING` off (`imply_option("MOZ_REQUIRE_SIGNING", False)` in
  `mail/moz.configure` on comm-central, comm-esr128 and comm-esr140) and the
  toolkit default of `xpinstall.signatures.required` is `false`
  (`modules/libpref/init/all.js`); Thunderbird does not override it.
  Sources: <https://hg-edge.mozilla.org/comm-central/raw-file/tip/mail/moz.configure>,
  <https://hg-edge.mozilla.org/releases/comm-esr140/raw-file/tip/mail/moz.configure>,
  <https://bugzilla.mozilla.org/show_bug.cgi?id=1549562>.
- **No "unverified" warning either.** TB 128/140 override `isCorrectlySigned`
  in the add-on manager (`mail/base/content/aboutAddonsExtra.js`); since TB 152
  (bug 2037408, so 153 ESR and current releases) the pref
  `extensions.ui.disableUnsignedWarnings` is `true` in `all-thunderbird.js`.
  The commit message of bug 2037408 says it plainly: Thunderbird shows the
  warning for all add-ons otherwise *"because we do not sign add-ons"*.
  <https://bugzilla.mozilla.org/show_bug.cgi?id=2037408>.
- **ATN packages are not signed.** A package downloaded from ATN (checked:
  Quicktext 6.9.5 from `addons.thunderbird.net/api/v4`) has no `META-INF/`
  signature files. So for Thunderbird, "signing" buys **nothing technically**;
  an ATN listing buys a review by the Thunderbird add-on team, discoverability
  (Add-ons Manager search) and **automatic updates from ATN** for users who
  installed from there.
- **Self-hosted updates work for unsigned add-ons.** Thunderbird keeps
  `extensions.update.enabled` on and checks the `update_url` of the installed
  add-on (comm-central has mochitests updating unsigned add-ons through an
  update JSON with `xpinstall.signatures.required=false`,
  `mail/base/test/browser/webextensions/browser_extension_update_background_noprompt.js`).
  The update manifest must be served over **https**; `update_link` must be
  https or carry `update_hash`. Format:
  <https://extensionworkshop.com/documentation/manage/updating-your-extension/>.
- **A listed store package must not contain `update_url`.** `web-ext lint`
  (addons-linter) reports `MANIFEST_UPDATE_URL` as an error unless run with
  `--self-hosted` - checked on our instance build. The generic build therefore
  has no `update_url`; the instance build has one.
- **ATN API**: ATN runs a fork of addons-server and exposes the v4 API at
  `https://addons.thunderbird.net/api/v4/` (used by `web-ext sign
  --amo-base-url` per <https://github.com/marketplace/actions/web-ext-action-for-firefox-add-ons>).
  Whether ATN accepts `--channel=unlisted` ("on your own") was **not**
  verified - no official page found. Since ATN does not sign anyway, an
  unlisted ATN submission would gain nothing over the self-hosted build.

## Thunderbird

### Builds

| Build | How | Contents |
|---|---|---|
| instance | `/plugin/download?build=instance`, `bin/console antispam:plugin:build --server=URL` | `config.json` with the URL, the host in `permissions`, `update_url` = `<URL>/plugin/thunderbird/updates.json` (https only) |
| generic | `/plugin/download?build=generic`, `bin/build-thunderbird-xpi --generic`, `bin/console antispam:plugin:build --generic` | the source as is: no `config.json`, no `update_url`; the user's server is granted through `optional_permissions` (`*://*/*`) when they save it |
| uploaded | panel: *Wtyczki pocztowe → Wgraj wersję ogólną* | a generic package (typically the file ATN serves after review), stored in `var/data/plugin/` (Docker volume `app-data`) |

`/plugin/download` without `build=` serves the **uploaded** package when one
of the current `PLUGIN_VERSION` is stored, otherwise the instance build. An
upload is accepted only when it is a zip with `manifest.json`, add-on id
`antispam@pancernapanda.pl`, version equal to `PLUGIN_VERSION` and **no
server URL** in `config.json` (another instance's package would send users'
mail there); max 5 MiB. After a server upgrade with a new plugin version the
old upload is shown as *nieaktualna* and no longer served until the new
reviewed file is uploaded. A package with `META-INF/mozilla.rsa` or
`cose.sig` is labelled *podpisana* (none from ATN are, today).

Builds are **reproducible**: entries sorted (`manifest.json` first), fixed
timestamp 2026-01-01, fixed permissions, junk files (`.DS_Store`, dotfiles)
skipped. Same source + URL + zlib = same bytes; CI checks this.

### Self-hosted updates (instance build)

`GET /plugin/thunderbird/updates.json` (public):

```json
{
  "addons": {
    "antispam@pancernapanda.pl": {
      "updates": [{
        "version": "1.2.0",
        "update_link": "https://antispam.example.pl/plugin/download?build=instance&v=1.2.0",
        "applications": {"gecko": {"strict_min_version": "115.0"}}
      }]
    }
  }
}
```

Thunderbird checks it daily (`extensions.update.interval` 86400 s) and
installs a higher version without asking (unless the update requests new
permissions). The link asks for the instance build explicitly, so an update
keeps the baked-in URL even when an uploaded generic package is the default
download. No `update_hash` is published: the package is built per request and
the link is https. Only builds made over https get `update_url`, so instances
reachable over http only have no automatic updates (shown in the panel).
Builds made before 1.2.0 have no `update_url` - users must install 1.2.0 by
hand once.

Users who installed from ATN get updates from ATN (no `update_url`); both
kinds share the add-on id, so a user should not mix them. If a user installs
the instance build over an ATN one, updates come from the instance from then
on.

### First run of the generic build

On install (`runtime.onInstalled`, reason `install`) without a server address
the plugin opens its settings tab. The page shows a **Pierwsze uruchomienie**
box: paste the address (or the `/plugin/setup` link), *Połącz* → Thunderbird
asks for the host permission → saved, the connection status appears. Until
then every action that needs the server opens the settings (as before). The
connection test reports which build is installed (*adres z pobranej wersji* /
*wersja ogólna*). Tested with mocked WebExtension APIs in
`tests/js/thunderbird-first-run.mjs`.

### Releasing a Thunderbird version to ATN (owner, one-time setup first)

One-time:

1. Create an account on <https://addons.thunderbird.net> (Developer Hub) with
   the address that should own the add-on.
2. Developer Hub → *Manage API Keys* → generate a JWT issuer + secret if you
   want CI submission. Store them as GitHub repository secrets
   **`ATN_API_KEY`** (issuer) and **`ATN_API_SECRET`**. Never commit them.
3. First version by hand: Developer Hub → *Submit a New Add-on* → *On this
   site* → upload `antispam-thunderbird-<version>.xpi` from the CI artifact
   (or `bin/build-thunderbird-xpi --generic`). Source code upload: not needed
   (plain, unminified JS). Fill in the listing (Polish), categories, a
   **privacy policy** - the add-on sends message sources to the server the
   user configures; mention that no data goes to the developer. ATN may ask
   to declare data collection: the manifest says
   `data_collection_permissions.required: ["none"]`; if the reviewer asks for
   a declaration such as `personalCommunications`, change it in
   `Resources/thunderbird/manifest.json` and bump the version.

Each release:

1. Bump `version` in `Resources/thunderbird/manifest.json` and
   `PluginApiController::PLUGIN_VERSION` (equal; [deployment.md](deployment.md#releasing)).
2. Tag `thunderbird-v<version>` and push the tag. The workflow
   `.github/workflows/thunderbird-plugin.yml` checks the versions, runs
   `node --check` + the first-run test, builds the generic package twice
   (byte-compare), runs `web-ext lint` and uploads the `.xpi` artifact. With
   the two secrets set it also runs
   `web-ext sign --amo-base-url=https://addons.thunderbird.net/api/v4/ --channel=listed`;
   without them (or if ATN's API refuses) it ends with a notice to upload by
   hand. Manual equivalent:

   ```bash
   bin/build-thunderbird-xpi --generic --output=build/antispam-thunderbird-1.2.0.xpi
   mkdir -p build/src && unzip -o build/antispam-thunderbird-1.2.0.xpi -d build/src
   npx web-ext@8 lint --source-dir=build/src          # 4 warnings: Thunderbird-only permissions
   WEB_EXT_API_KEY=... WEB_EXT_API_SECRET=... \
     npx web-ext@8 sign --source-dir=build/src --channel=listed \
       --amo-base-url=https://addons.thunderbird.net/api/v4/ --approval-timeout=0
   ```
3. After ATN approves the version, download its file from the ATN listing
   and upload it in every instance panel (*Wtyczki pocztowe → Wgraj wersję
   ogólną*) - or skip this step and keep serving the instance build.

## Outlook

### Manifest formats (status October 2026)

- The **add-in only (XML) manifest** we use remains supported everywhere
  Outlook add-ins run (classic and new Outlook for Windows, web, Mac,
  mobile) and is the only format Outlook on Mac and mobile accept.
- The **unified manifest for Microsoft 365** (JSON, app package) is
  supported in Outlook on the web, new Outlook for Windows and classic
  Outlook for Windows 2307+ with a Microsoft 365 subscription; **not** in
  Outlook on Mac, mobile, perpetual Office, nor for mailboxes on on-premises
  Exchange. Microsoft recommends shipping two versions if you need both.
  <https://learn.microsoft.com/en-us/office/dev/add-ins/develop/unified-manifest-overview>
  (updated 2026-10-14).

So the XML manifest stays; a JSON variant would only add a second artefact
without new features (our pane needs nothing unified-only).

### Centralized deployment (owner / tenant admin)

1. Panel: set **Publiczny adres** to `https://…` (Outlook refuses http).
2. Download `antispam-outlook.xml` (*Wtyczki pocztowe*) - or use its URL
   `https://<instance>/plugin/outlook/manifest.xml`.
3. Microsoft 365 admin center → *Settings → Integrated apps* → *Upload custom
   apps* (or the *Add-ins* link → *Deploy Add-in* → *Upload custom apps*) →
   *Office Add-in* → upload the manifest file or provide its URL.
4. Assign: *Just me* (test) → a group → *Everyone*. Groups are easiest.
5. Wait: the button can take **24-72 h** to appear; users may need to restart
   Outlook.
6. A new manifest `<Version>` (e.g. a changed URL) must be uploaded again:
   select the add-in → *Update*.

Source: <https://learn.microsoft.com/en-us/microsoft-365/admin/manage/manage-deployment-of-add-ins>
(updated 2026-05-06). The admin-center "Add-in" portal accepts only XML
manifests; unified manifests go through *Integrated apps*.

Our manifest has everything the deployment needs: GUID `Id`, four-part
`Version`, `ProviderName`, `DefaultLocale`, `DisplayName`, `Description`,
`IconUrl` (64 px) + `HighResolutionIconUrl` (128 px), `SupportUrl`,
`AppDomains`, `Hosts`/`Requirements`, `Permissions` `ReadItem`, https URLs.
**Not checked with Microsoft's validator**: `npx office-addin-manifest
validate` sends the manifest to Microsoft's online validation service, which
this environment did not use; run it on the downloaded manifest before a
rollout.

### Outlook AppSource

Microsoft Marketplace (AppSource) needs a Partner Center account, the
Marketplace certification policies (<https://learn.microsoft.com/en-us/legal/marketplace/certification-policies>),
a privacy policy, support and terms URLs, test credentials for the reviewers
and **one manifest with fixed https URLs**
(<https://learn.microsoft.com/en-us/office/dev/add-ins/publish/publish-office-add-ins-to-appsource>).
Our task pane is loaded from each instance (same-origin API, no CORS), so a
store manifest cannot point at "the user's server". Options:

1. **Central task pane** (`https://antispam.pancernapanda.pl/plugin/outlook/`)
   with a server field like the Thunderbird first run, storing the address in
   roaming settings, and **CORS** on `/api/plugin/*` of every instance (the
   pane would call another origin). Code changes: server field in
   `taskpane.js`, CORS headers + preflight on the API. One store listing;
   every instance must be reachable over https from the user's browser.
2. **One listing per hosted instance** - only for instances run by the owner.
3. **Stay with centralized deployment** (recommended): tenants deploy the
   manifest of their instance; no store review, no per-instance problem.

Option 1 is not implemented.

## Apple Mail

### Requirements (verified 2026-10-28)

- Mail extensions are **MailKit app extensions inside a macOS app**; legacy
  `.mailbundle` plug-ins are not loaded by current Mail.
- Outside the Mac App Store the app must be signed with a **Developer ID
  Application** certificate (Apple Developer Program, 99 USD/year), with the
  hardened runtime and a secure timestamp, and **notarized** (`notarytool`,
  Xcode 13+; `altool` is no longer accepted), then the ticket **stapled**.
  Accepted uploads: zip, dmg, pkg; a zip cannot be stapled, so staple the
  `.app` and zip again.
  <https://developer.apple.com/documentation/security/customizing-the-notarization-workflow>
- Mac App Store uploads must be built with **Xcode 26+** since 2026-04-28
  (<https://developer.apple.com/news/upcoming-requirements/>); Developer ID
  builds have no such rule, but use a current Xcode anyway. Xcode 26.4+ needs
  macOS 26.2.
- This machine has only the Command Line Tools (`xcodebuild` unavailable),
  so no `xcodebuild` build was possible. `swiftc -typecheck` of `Shared/` +
  `MailExtension/` against the macOS 27 SDK (MailKit) passes; the SwiftUI app
  cannot be type-checked without Xcode (SwiftUI macro plug-ins missing);
  `ServerConfig.normalize` was compiled and run against test cases.

### One signed app for every instance

The app already reads the server URL from its settings (App Group defaults)
and falls back to the baked-in `ServerConfig.bundledServer`. A build from the
repository keeps the placeholder, so the field is empty on first run and the
window says *Podaj adres serwera…*; the setter now normalises a pasted setup
link (`ServerConfig.normalize`, same rules as the Thunderbird plugin). The
per-instance source zip still bakes the URL in.

### Build, sign, notarize (owner's Mac)

```bash
brew install xcodegen
xcode-select -s /Applications/Xcode.app
# once: keychain profile for notarytool (app-specific password from appleid.apple.com)
xcrun notarytool store-credentials antispam-notary \
    --apple-id you@example.com --team-id ABCDE12345 --password xxxx-xxxx-xxxx-xxxx

src/AntispamBundle/Resources/applemail/scripts/build-and-notarize.sh --unsigned   # compile check
TEAM_ID=ABCDE12345 MAKE_DMG=1 src/AntispamBundle/Resources/applemail/scripts/build-and-notarize.sh
```

The script: `xcodegen generate` → `xcodebuild archive` (Developer ID team,
hardened runtime, `--timestamp`, `-allowProvisioningUpdates`) →
`-exportArchive` with `method developer-id` → `codesign --verify` →
`notarytool submit --wait` → `stapler staple` + `validate` → `spctl
--assess` → `build/AntispamMail-<version>.zip` (and `.dmg` with
`MAKE_DMG=1`, signed, notarized and stapled too). Variables: `TEAM_ID`,
`NOTARY_PROFILE` (default `antispam-notary`), `VERSION`, `BUILD_NUMBER`,
`OUT_DIR`, `MAKE_DMG`, `SKIP_NOTARIZE`. No secrets in the script.

Distribute the zip / dmg from any https location; users copy the app to
`/Applications`, run it once, paste the server address, then enable it in
*Mail → Settings → Extensions*. If Xcode reports App Group / provisioning
problems, open the project, select the team in *Signing & Capabilities* for
both targets and let Xcode create the Developer ID profiles once.

## What the owner has to do (summary)

1. **ATN** (optional): account, first listing by hand, API key as GitHub
   secrets `ATN_API_KEY` / `ATN_API_SECRET`, then tag `thunderbird-v<version>`
   per release; upload the reviewed file into the panel.
2. **Instances**: set *Publiczny adres* to https (auto-updates and Outlook
   need it); give users the `/plugin/setup` link when they use the ATN build.
3. **Outlook**: tenant admin uploads the instance manifest in *Integrated
   apps*; run `npx office-addin-manifest validate antispam-outlook.xml` once.
4. **Apple**: Developer Program membership, Developer ID certificate,
   `notarytool store-credentials`, run `build-and-notarize.sh`, publish the
   zip / dmg.
