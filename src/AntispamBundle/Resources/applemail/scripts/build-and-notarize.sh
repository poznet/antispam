#!/usr/bin/env bash
#
# Builds, signs (Developer ID), notarizes and staples the Antispam Pancernapanda
# Mail extension app on the owner's Mac. No secrets in this file: the Apple ID
# credentials live in a notarytool keychain profile created once with
#
#   xcrun notarytool store-credentials antispam-notary \
#       --apple-id you@example.com --team-id ABCDE12345 --password <app-specific-password>
#
# (or --key/--key-id/--issuer for an App Store Connect API key).
#
# Usage (from anywhere):
#   TEAM_ID=ABCDE12345 src/AntispamBundle/Resources/applemail/scripts/build-and-notarize.sh
#   src/AntispamBundle/Resources/applemail/scripts/build-and-notarize.sh --unsigned   # compile check only
#
# Variables (environment):
#   TEAM_ID          Apple Developer Team ID (required unless --unsigned)
#   NOTARY_PROFILE   notarytool keychain profile name (default: antispam-notary)
#   VERSION          MARKETING_VERSION override (default: from project.yml)
#   BUILD_NUMBER     CURRENT_PROJECT_VERSION override (default: from project.yml)
#   OUT_DIR          output directory (default: <applemail>/build)
#   MAKE_DMG=1       also produce a notarized + stapled .dmg
#   SKIP_NOTARIZE=1  sign only (e.g. to test the archive first)
#
# Needs: macOS with full Xcode (xcode-select -s /Applications/Xcode.app),
# XcodeGen (brew install xcodegen), a "Developer ID Application" certificate in
# the login keychain for TEAM_ID. Output: build/AntispamMail-<version>.zip
# (stapled .app inside) and optionally .dmg. See docs/plugin-distribution.md.
#
# The app is built from the repository source, so it has no server URL baked
# in (ServerConfig placeholder): one signed app works for every antispam
# instance, the user enters / pastes the address on first run.

set -euo pipefail

UNSIGNED=0
[[ "${1:-}" == "--unsigned" ]] && UNSIGNED=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$HERE/build}"
NOTARY_PROFILE="${NOTARY_PROFILE:-antispam-notary}"
SCHEME="AntispamMail"
APP_NAME="Antispam Pancernapanda"

die() { echo "error: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

command -v xcodebuild >/dev/null || die "xcodebuild not found"
xcodebuild -version >/dev/null 2>&1 || die "full Xcode is required (xcode-select -p shows Command Line Tools?)"
command -v xcodegen >/dev/null || die "XcodeGen not found: brew install xcodegen"
if [[ $UNSIGNED -eq 0 ]]; then
    [[ -n "${TEAM_ID:-}" ]] || die "set TEAM_ID (Apple Developer Team ID) or use --unsigned"
    security find-identity -v -p codesigning | grep -q "Developer ID Application: .*(${TEAM_ID})" \
        || die "no 'Developer ID Application' certificate for team $TEAM_ID in the keychain"
fi

grep -q '__ANTISPAM_SERVER__' "$HERE/Shared/ServerConfig.swift" \
    || echo "warning: ServerConfig.swift has a baked-in server URL - this build only fits one instance" >&2

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/antispam-applemail.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

step "Generating the Xcode project (XcodeGen)"
(cd "$HERE" && xcodegen generate --quiet)

OVERRIDES=()
[[ -n "${VERSION:-}" ]] && OVERRIDES+=("MARKETING_VERSION=$VERSION")
[[ -n "${BUILD_NUMBER:-}" ]] && OVERRIDES+=("CURRENT_PROJECT_VERSION=$BUILD_NUMBER")

if [[ $UNSIGNED -eq 1 ]]; then
    step "Unsigned build (compile check, not distributable)"
    xcodebuild -project "$HERE/AntispamMail.xcodeproj" -scheme "$SCHEME" -configuration Release \
        -derivedDataPath "$WORK/dd" CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
        ${OVERRIDES[@]+"${OVERRIDES[@]}"} build
    echo "OK: $(find "$WORK/dd" -name "$APP_NAME.app" -maxdepth 5 | head -1)"
    exit 0
fi

ARCHIVE="$WORK/AntispamMail.xcarchive"
step "Archiving (Developer ID, hardened runtime)"
xcodebuild -project "$HERE/AntispamMail.xcodeproj" -scheme "$SCHEME" -configuration Release \
    -destination 'generic/platform=macOS' -archivePath "$ARCHIVE" \
    DEVELOPMENT_TEAM="$TEAM_ID" CODE_SIGN_STYLE=Automatic ENABLE_HARDENED_RUNTIME=YES \
    OTHER_CODE_SIGN_FLAGS="--timestamp" -allowProvisioningUpdates \
    ${OVERRIDES[@]+"${OVERRIDES[@]}"} archive

cat > "$WORK/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>developer-id</string>
    <key>teamID</key><string>${TEAM_ID}</string>
    <key>signingStyle</key><string>automatic</string>
    <key>destination</key><string>export</string>
</dict>
</plist>
PLIST

step "Exporting with Developer ID"
xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportPath "$WORK/export" \
    -exportOptionsPlist "$WORK/ExportOptions.plist" -allowProvisioningUpdates
APP="$WORK/export/$APP_NAME.app"
[[ -d "$APP" ]] || die "exported app not found at $APP"

step "Verifying the signature"
codesign --verify --deep --strict --verbose=2 "$APP"
codesign -d --entitlements - "$APP/Contents/PlugIns/"*.appex >/dev/null

VER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP/Contents/Info.plist")"
ZIP="$OUT_DIR/AntispamMail-$VER.zip"

if [[ "${SKIP_NOTARIZE:-0}" == "1" ]]; then
    ditto -c -k --keepParent "$APP" "$ZIP"
    echo "Signed, NOT notarized: $ZIP"
    exit 0
fi

step "Notarizing (notarytool, profile $NOTARY_PROFILE)"
ditto -c -k --keepParent "$APP" "$WORK/upload.zip"
xcrun notarytool submit "$WORK/upload.zip" --keychain-profile "$NOTARY_PROFILE" --wait
# A ZIP cannot be stapled: staple the app, then zip it again.
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=2 "$APP"
ditto -c -k --keepParent "$APP" "$ZIP"
echo "Notarized and stapled: $ZIP"

if [[ "${MAKE_DMG:-0}" == "1" ]]; then
    step "Building the .dmg"
    DMG="$OUT_DIR/AntispamMail-$VER.dmg"
    mkdir -p "$WORK/dmg" && cp -R "$APP" "$WORK/dmg/" && ln -s /Applications "$WORK/dmg/Applications"
    hdiutil create -volname "$APP_NAME" -srcfolder "$WORK/dmg" -ov -format UDZO "$DMG"
    codesign --sign "Developer ID Application" --timestamp "$DMG"
    xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
    echo "Notarized and stapled: $DMG"
fi

shasum -a 256 "$OUT_DIR"/AntispamMail-"$VER".*
