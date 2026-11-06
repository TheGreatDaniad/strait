#!/bin/bash
# Assemble Strait.app (with the design's icon) from a built binary and ad-hoc sign it.
# usage: macos/make-bundle.sh [binary] [dest-dir]   (defaults: target/release/nat-tunnel, ~/Applications)
# Run the GUI as root from the bundle: sudo ~/Applications/Strait.app/Contents/MacOS/nat-tunnel gui
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$HERE/target/release/nat-tunnel}"
DEST="${2:-$HOME/Applications}"
APP="$DEST/Strait.app"
[ -x "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 1; }

SET="$(mktemp -d)/AppIcon.iconset"; mkdir -p "$SET"
L="$HERE/assets/logo"
cp "$L/app-icon-16.png"   "$SET/icon_16x16.png";      cp "$L/app-icon-32.png"   "$SET/icon_16x16@2x.png"
cp "$L/app-icon-32.png"   "$SET/icon_32x32.png";      cp "$L/app-icon-64.png"   "$SET/icon_32x32@2x.png"
cp "$L/app-icon-128.png"  "$SET/icon_128x128.png";    cp "$L/app-icon-256.png"  "$SET/icon_128x128@2x.png"
cp "$L/app-icon-256.png"  "$SET/icon_256x256.png";    cp "$L/app-icon-512.png"  "$SET/icon_256x256@2x.png"
cp "$L/app-icon-512.png"  "$SET/icon_512x512.png";    cp "$L/app-icon-1024.png" "$SET/icon_512x512@2x.png"

rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/nat-tunnel"
cp "$HERE/macos/Info.plist" "$APP/Contents/Info.plist"
iconutil -c icns "$SET" -o "$APP/Contents/Resources/AppIcon.icns"
codesign --force --sign - "$APP"
echo "installed: $APP"
