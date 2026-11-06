#!/bin/bash
# Build libstrait_ios.a (device + simulator) from ../../nat-tunnel and wrap it in Strait.xcframework.
# Usage: ios/build-rust.sh   (env: CARGO_TARGET_DIR to relocate the build, PROFILE=release|debug)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$HERE/../../nat-tunnel"
PROFILE="${PROFILE:-release}"
FEATURES="ffi,rv-trk,rv-nostr,rv-dht,rv-ntfy,rv-mqtt"   # default features minus the desktop gui
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$CRATE/target-ios}"
export IPHONEOS_DEPLOYMENT_TARGET=15.1
# Apple's nm/ld cannot read the newer-LLVM bitcode rustc embeds (LTO needs it): build without LTO/bitcode.
export RUSTFLAGS="${RUSTFLAGS:-} -C embed-bitcode=no"
export CARGO_PROFILE_RELEASE_LTO=off
FLAG=(); [ "$PROFILE" = release ] && FLAG=(--release)

for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  case "$t" in *-sim|x86_64*) sdk=iphonesimulator ;; *) sdk=iphoneos ;; esac
  # cc-rs finds the SDK itself; SDKROOT makes it explicit for the C backends (ring, secp256k1-sys).
  SDKROOT="$(xcrun --sdk $sdk --show-sdk-path)" \
    cargo build ${FLAG[@]+"${FLAG[@]}"} --lib --target "$t" --no-default-features --features "$FEATURES" \
    --manifest-path "$CRATE/Cargo.toml"
done

OUT="$HERE/build/strait-lib"; rm -rf "$OUT" "$HERE/Strait.xcframework"
mkdir -p "$OUT/dev" "$OUT/sim" "$OUT/include"
B="$CARGO_TARGET_DIR"
cp "$B/aarch64-apple-ios/$PROFILE/libnat_tunnel.a" "$OUT/dev/libstrait_ios.a"
lipo -create "$B/aarch64-apple-ios-sim/$PROFILE/libnat_tunnel.a" "$B/x86_64-apple-ios/$PROFILE/libnat_tunnel.a" \
  -output "$OUT/sim/libstrait_ios.a"
cp "$CRATE/include/strait.h" "$OUT/include/"
printf 'module Strait {\n  header "strait.h"\n  export *\n}\n' > "$OUT/include/module.modulemap"
xcodebuild -create-xcframework \
  -library "$OUT/dev/libstrait_ios.a" -headers "$OUT/include" \
  -library "$OUT/sim/libstrait_ios.a" -headers "$OUT/include" \
  -output "$HERE/Strait.xcframework"
echo "built $HERE/Strait.xcframework"
