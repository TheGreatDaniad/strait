#!/bin/bash
# Build, install and launch Strait on a connected iPhone, then tail its console.
# Usage: DEVELOPMENT_TEAM=ABCDE12345 [STRAIT_BUNDLE_BASE=com.you.strait] [DEVICE=<udid|name>] ios/device-test.sh
# Needs: paid Apple Developer team (Network Extension), Developer Mode on, phone unlocked + trusted,
#        ios/build-rust.sh already run, `pod install` already run in ios/.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${DEVELOPMENT_TEAM:?set DEVELOPMENT_TEAM to your 10-char Apple Team ID}"
BASE="${STRAIT_BUNDLE_BASE:-$(sed -n 's/^STRAIT_BUNDLE_BASE *= *//p' "$HERE/Signing.xcconfig")}"
DD="${DERIVED_DATA:-$HERE/build/DerivedData}"
free_gb=$(df -g /System/Volumes/Data | awk 'NR==2{print $4}')
[ "$free_gb" -ge 8 ] || { echo "only ${free_gb} GB free; need >= 8 GB for a device build" >&2; exit 1; }

# Pick the device: explicit DEVICE, else the first connected one.
if [ -z "${DEVICE:-}" ]; then
  DEVICE=$(xcrun devicectl list devices 2>/dev/null | awk '/connected|available \(paired\)/{print $3; exit}')
fi
[ -n "${DEVICE:-}" ] || { echo "no connected device found (xcrun devicectl list devices)" >&2; exit 1; }
echo "device: $DEVICE  team: $DEVELOPMENT_TEAM  bundle: $BASE"

WS="$HERE/StraitMobile.xcworkspace"
[ -d "$WS" ] || { echo "missing $WS: run 'cd ios && pod install' first" >&2; exit 1; }
xcodebuild -workspace "$WS" -scheme StraitMobile -configuration Debug \
  -destination "id=$DEVICE" -derivedDataPath "$DD" \
  DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM" STRAIT_BUNDLE_BASE="$BASE" \
  -allowProvisioningUpdates build

APP=$(ls -d "$DD"/Build/Products/Debug-iphoneos/StraitMobile.app)
xcrun devicectl device install app --device "$DEVICE" "$APP"
echo "launching with console (Ctrl-C to stop). Extension logs: idevicesyslog | grep -i strait"
if command -v idevicesyslog >/dev/null; then
  (idevicesyslog -u "$DEVICE" 2>/dev/null | grep --line-buffered -i "strait\|PacketTunnel" > "$HERE/build/device-syslog.txt" &) 
  echo "syslog -> $HERE/build/device-syslog.txt"
fi
xcrun devicectl device process launch --device "$DEVICE" --console --terminate-existing "$BASE"
