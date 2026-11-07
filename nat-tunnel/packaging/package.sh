#!/bin/bash
# Assemble the release packages from built binaries.
# usage: packaging/package.sh <cargo-target-dir> <out-dir>   (needs the five release builds under <cargo-target-dir>/<triple>/release)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="${1:?target dir}"; OUT="${2:?out dir}"; mkdir -p "$OUT"
V="$(grep -m1 '^version' "$HERE/Cargo.toml" | cut -d'"' -f2)"
bin() { echo "$T/$1/release/nat-tunnel${2:-}"; }
ICONS="$HERE/assets/logo"

# Linux: .deb (menu entry, icons, GUI libraries as dependencies) and a plain tarball per architecture
for pair in "x86_64-unknown-linux-gnu amd64 x64" "aarch64-unknown-linux-gnu arm64 arm64"; do
  set -- $pair
  python3 "$HERE/packaging/make_deb.py" "$(bin $1)" "$V" "$2" "$ICONS" "$OUT/strait_${V}_$2.deb"
  S="$(mktemp -d)/strait-$V-linux-$3"; mkdir -p "$S"; cp "$(bin $1)" "$S/nat-tunnel"
  printf 'Run the app (it asks for your password when it needs to):\n  sudo ./nat-tunnel gui\nCommand line help:\n  ./nat-tunnel --help\n' > "$S/README.txt"
  tar -C "$(dirname "$S")" -czf "$OUT/strait-$V-linux-$3.tar.gz" "$(basename "$S")"
done

# macOS: one universal app in a disk image
U="$(mktemp -d)"; lipo -create "$(bin aarch64-apple-darwin)" "$(bin x86_64-apple-darwin)" -output "$U/nat-tunnel"
D="$(mktemp -d)"; bash "$HERE/macos/make-bundle.sh" "$U/nat-tunnel" "$D" >/dev/null
ln -s /Applications "$D/Applications"
hdiutil create -quiet -volname "Strait" -srcfolder "$D" -ov -format UDZO "$OUT/strait-$V-macos-universal.dmg"

# Windows: exe + the Wintun driver library (pinned SHA-256), unpacked next to each other
W="$(mktemp -d)/strait-$V-windows-x64"; mkdir -p "$W"; cp "$(bin x86_64-pc-windows-gnu .exe)" "$W/Strait.exe"
WT="$(mktemp -d)"; curl -sfL -o "$WT/w.zip" https://www.wintun.net/builds/wintun-0.14.1.zip
echo "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51  $WT/w.zip" | shasum -a 256 -c - >/dev/null
python3 -I -c "import zipfile,sys; open(sys.argv[2],'wb').write(zipfile.ZipFile(sys.argv[1]).read('wintun/bin/amd64/wintun.dll'))" "$WT/w.zip" "$W/wintun.dll"
cat > "$W/README.txt" <<'TXT'
Strait for Windows
1. Keep Strait.exe and wintun.dll in the same folder.
2. Double-click Strait.exe and answer Yes to the administrator prompt (the tunnel needs it).
3. Host: Host tab > Start sharing > send the invite. Client: paste the invite on the Connect tab.
If Windows SmartScreen warns about an unknown publisher, choose More info > Run anyway (the app is not code-signed).
If the window does not open, a message box explains why; the same text is saved in %TEMP%\strait-gui-error.txt.
wintun.dll is the Wintun driver library, version 0.14.1 (https://www.wintun.net).
TXT
(cd "$(dirname "$W")" && zip -qr "$OUT/strait-$V-windows-x64.zip" "$(basename "$W")")
(cd "$OUT" && shasum -a 256 strait* > SHA256SUMS && cat SHA256SUMS)
