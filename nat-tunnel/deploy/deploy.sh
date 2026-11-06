#!/usr/bin/env bash
# Deploy strait-host (and optionally strait-signal) on the VPS. Run as root ON the VPS,
# from this directory, with the Linux x86_64 binary built (see below).
#
# Build (pick one):
#   on VPS:      cargo build --release                     -> target/release/nat-tunnel
#   cross, mac:  cargo install cargo-zigbuild && rustup target add x86_64-unknown-linux-gnu
#                cargo zigbuild --release --target x86_64-unknown-linux-gnu
#                (binary: target/x86_64-unknown-linux-gnu/release/nat-tunnel; scp it over with the units)
#
# Usage: deploy.sh [--dry-run] [--print-units] [--rotate] [--with-signal] [--bin PATH] [--host-args "ARGS"]
#   --print-units  print the unit files that would be installed and exit (touches nothing)
# Test hooks (see selftest.sh): DEST_ROOT=<dir> stages every write under <dir> and skips the
# root/Linux/binary checks; SYSTEMCTL / UFW override those commands (e.g. SYSTEMCTL=echo).
set -euo pipefail

ENDPOINT="203.0.113.10:7100"
LAB_KEY="0123456789abcdef0123456789abcdef"
DEST_ROOT="${DEST_ROOT:-}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
UFW="${UFW:-ufw}"
ENV_DIR="$DEST_ROOT/etc/strait"
ENV_FILE="$ENV_DIR/host.env"
UNIT_DIR="$DEST_ROOT/etc/systemd/system"
BIN_DST="$DEST_ROOT/usr/local/bin/nat-tunnel"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="$HERE/nat-tunnel"
DRY=0 ROTATE=0 SIGNAL=0 PRINT=0
# Multiplexed host, userspace exit: no TUN, no capabilities. --tun only selects the
# multiplexed mode (its address is overridden to 10.7.0.1/16); --userspace skips the device.
# For kernel TUN + NAT instead, see SELF_HOSTING.md ("TUN exit").
HOST_ARGS="--tun 10.7.0.1/16 --userspace --max-clients 8"

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --print-units) PRINT=1 ;;
    --rotate) ROTATE=1 ;;
    --with-signal) SIGNAL=1 ;;
    --bin) BIN_SRC="$2"; shift ;;
    --host-args) HOST_ARGS="$2"; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [ "$PRINT" = 1 ]; then
  for u in strait-host.service strait-signal.service; do echo "# ---- $u"; cat "$HERE/$u"; done
  exit 0
fi

run() { if [ "$DRY" = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }
die() { echo "error: $*" >&2; exit 1; }

if [ "$DRY" = 0 ] && [ -z "$DEST_ROOT" ]; then
  [ "$(id -u)" = 0 ] || die "run as root"
  [ "$(uname -s)" = Linux ] || die "must run on the Linux VPS"
fi
[ "$DRY" = 1 ] || [ -x "$BIN_SRC" ] || die "binary not found: $BIN_SRC (use --bin)"

# Key handling: keep, refuse lab key, or rotate.
existing=""
if [ -f "$ENV_FILE" ]; then
  existing="$(grep -o 'STRAIT2|[0-9a-f]*' "$ENV_FILE" | head -1 | cut -d'|' -f2 || true)"
  if [ "$existing" = "$LAB_KEY" ]; then
    echo "refusing: $ENV_FILE contains the throwaway lab key; re-run with --rotate" >&2
    [ "$ROTATE" = 1 ] || exit 1
  fi
  if [ -n "$existing" ] && [ "$ROTATE" = 0 ]; then
    echo "existing key kept ($ENV_FILE); use --rotate to replace it"
  fi
fi
if [ -n "$existing" ] && [ "$ROTATE" = 0 ]; then
  KEY="$existing"; NEWKEY=0
else
  KEY="$(openssl rand -hex 16)"
  [ "$KEY" != "$LAB_KEY" ] || die "generated the lab key (impossible); retry"
  NEWKEY=1
fi
INVITE="STRAIT2|$KEY|$ENDPOINT"

echo "== install binary and units"
run mkdir -p "$(dirname "$BIN_DST")" "$UNIT_DIR"
run install -m 0755 "$BIN_SRC" "$BIN_DST"
run install -m 0644 "$HERE/strait-host.service" "$UNIT_DIR/strait-host.service"
if [ "$SIGNAL" = 1 ]; then
  run install -m 0644 "$HERE/strait-signal.service" "$UNIT_DIR/strait-signal.service"
fi

echo "== write $ENV_FILE (0600)"
if [ "$NEWKEY" = 1 ]; then
  if [ "$DRY" = 1 ]; then
    echo "[dry-run] install -d -m 0755 $ENV_DIR; write STRAIT_INVITE=<new key> + STRAIT_HOST_ARGS='$HOST_ARGS' to $ENV_FILE (umask 077)"
  else
    install -d -m 0755 "$ENV_DIR"
    # DynamicUser reads EnvironmentFile via systemd (root), so 0600 root is fine.
    ( umask 077; printf 'STRAIT_INVITE=%s\nSTRAIT_HOST_ARGS=%s\n' "$INVITE" "$HOST_ARGS" > "$ENV_FILE.tmp" )
    chmod 0600 "$ENV_FILE.tmp"; mv "$ENV_FILE.tmp" "$ENV_FILE"
  fi
fi

echo "== firewall"
if command -v "$UFW" >/dev/null 2>&1; then
  run "$UFW" allow 7100/udp
  if [ "$SIGNAL" = 1 ]; then run "$UFW" allow 7000/udp; fi
else
  echo "ufw not found: open UDP 7100$([ "$SIGNAL" = 1 ] && echo ' and 7000') yourself"
fi

echo "== services"
run "$SYSTEMCTL" daemon-reload
run "$SYSTEMCTL" enable strait-host.service
run "$SYSTEMCTL" restart strait-host.service
if [ "$SIGNAL" = 1 ]; then echo "strait-signal installed but NOT enabled; enable with: systemctl enable --now strait-signal"; fi

echo
echo "Invite (share only with people you trust; it is the whole capability):"
if [ "$DRY" = 1 ] && [ "$NEWKEY" = 1 ]; then echo "STRAIT2|<new random 128-bit key>|$ENDPOINT"; else echo "$INVITE"; fi
