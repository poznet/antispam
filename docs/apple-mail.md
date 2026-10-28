# Apple Mail extension (source only)

Status: **source code, no prebuilt app** ("wkrótce" in the UI).

## Why not a download like Thunderbird / Outlook

- Legacy Mail plug-ins (`.mailbundle`) are blocked on current macOS.
- The supported route is a **MailKit Mail extension** (macOS 12+), which ships
  inside a regular macOS app and must be built with Xcode and **signed with an
  Apple Developer ID** (and notarised to run on other Macs, or distributed via
  the Mac App Store). A server cannot produce that per instance.

So the app offers the Xcode source with the server URL baked in, and an admin
with an Apple Developer account builds and distributes the app.

Source: `src/AntispamBundle/Resources/applemail/` (build instructions in its
`README.md`, in Polish, shipped inside the zip). Download:
`GET /plugin/apple-mail/source.zip` (public; linked from *Konfiguracja →
Wtyczki pocztowe*), built by `MailClientPluginBuilder::appleMailSourceZip()`,
which replaces `__ANTISPAM_SERVER__` in `Shared/ServerConfig.swift`.

## Layout

| Path | |
|---|---|
| `project.yml` | XcodeGen spec: app target + Mail extension target, macOS 13+ |
| `App/` | SwiftUI container app: server URL, login, options, report by drag & drop / `.eml` |
| `MailExtension/MailExtension.swift` | `MEExtension` principal class |
| `MailExtension/MessageActionHandler.swift` | `MEMessageActionHandler` – on-arrival check |
| `Shared/AntispamClient.swift` | `/api/plugin/*` client (status, login, report, check) |
| `Shared/AntispamSettings.swift` | settings in App Group `UserDefaults` (shared app ↔ extension) |
| `*.entitlements` | sandbox, outgoing network, App Group `$(TeamIdentifierPrefix)pl.pancernapanda.antispam` |

## Behaviour

- **On-arrival check** (logged in, option on): Mail calls the message action
  handler for every downloaded message; if it is addressed to the logged-in
  mailbox (recipients or `Delivered-To` / `X-Original-To` / `Envelope-To`), the
  first 1 MiB of the raw message is sent to `/api/plugin/check`. Decision:
  `spam` → move to Junk (or red flag, or nothing), `quarantine` → orange
  background (optional). Headers-only calls return `invokeAgainWithBody`.
  Errors leave the message alone. Better than Outlook here: MailKit can act on
  arrival.
- **Reports:** Mail does not let extensions add buttons to a displayed message
  nor tells them when the user marks junk, so reports go through the app window:
  drag messages from Mail onto it (or pick `.eml` files) → `/api/plugin/report`
  (spam anonymous or logged in, "To nie spam" logged in).
- Login, token lifetime, rate limits, settings (`plugin.*`) — as for Thunderbird.

## Verified / not verified

- `MailExtension/*.swift` + `Shared/*.swift` type-check against the macOS SDK
  MailKit headers with `swiftc -typecheck` (Command Line Tools only).
- The SwiftUI app could not be type-checked without full Xcode (SwiftUI macros
  plugin missing in Command Line Tools); it has not been built, signed or run.
- `NSExtension` keys: `MEExtensionCapabilities` / `MEMessageActionHandler` were
  read from MailKit constants; `com.apple.email.extension` and
  `MEMessageActionDescription` follow Xcode's Mail Extension template — compare
  with a freshly generated target if Xcode complains.
