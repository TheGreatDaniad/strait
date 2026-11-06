#!/usr/bin/env bash
# Native macOS TUN test against the Docker lab.
#
#   cargo build
#   TUN=1 docker compose up -d internet router-a router-b relay peer-a
#   sudo ./scripts/mac_tun_e2e.sh
#
# Safety: this script NEVER changes the default route. The only routing change
# is a single /32 host route for 172.28.1.2 through the utun interface, which is
# removed on exit and by a watchdog. The default route is captured before and
# compared afterwards; a mismatch is reported as a failure.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo: sudo $0" >&2
    exit 1
fi

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/target/debug/nat-tunnel"
TUN_ADDR="10.7.0.2/24"
TARGET="172.28.1.2"
PORT="8000"
LOG="/tmp/nat-tunnel-mac-guest.log"
WATCHDOG_SECS="240"

[ -x "$BIN" ] || { echo "missing $BIN; run 'cargo build' first" >&2; exit 1; }

default_route() {
    route -n get default 2>/dev/null | awk '/gateway:|interface:/ {print $1, $2}'
}

BEFORE="$(default_route)"
if [ -z "$BEFORE" ]; then
    echo "could not read the current default route; aborting" >&2
    exit 1
fi

# Refuse to hijack an address that is already routed somewhere real.
CURRENT_IF="$(route -n get "$TARGET" 2>/dev/null | awk '/interface:/ {print $2}')" || true
if [ -n "$CURRENT_IF" ] && [ "$CURRENT_IF" != "en0" ]; then
    echo "$TARGET already routes via $CURRENT_IF; aborting" >&2
    exit 1
fi

GUEST_PID=""
WATCHDOG_PID=""

cleanup() {
    set +e
    route -n delete -host "$TARGET" >/dev/null 2>&1
    if [ -n "$WATCHDOG_PID" ]; then kill "$WATCHDOG_PID" 2>/dev/null; fi
    if [ -n "$GUEST_PID" ]; then
        kill "$GUEST_PID" 2>/dev/null
        wait "$GUEST_PID" 2>/dev/null
    fi
    AFTER="$(default_route)"
    if [ "$BEFORE" = "$AFTER" ]; then
        echo "default route unchanged:"
        echo "$AFTER"
    else
        echo "WARNING: default route changed!" >&2
        echo "before: $BEFORE" >&2
        echo "after:  $AFTER" >&2
    fi
}
trap cleanup EXIT INT TERM

: > "$LOG"
RUST_LOG="${RUST_LOG:-info}" "$BIN" guest \
    --relay 127.0.0.1:7000 \
    --room e2e \
    --key e2e-secret \
    --tun "$TUN_ADDR" >"$LOG" 2>&1 &
GUEST_PID=$!

# Hard stop even if everything above hangs.
(
    sleep "$WATCHDOG_SECS"
    route -n delete -host "$TARGET" >/dev/null 2>&1
    [ -n "$GUEST_PID" ] && kill "$GUEST_PID" 2>/dev/null
) &
WATCHDOG_PID=$!

IFACE=""
for _ in $(seq 1 60); do
    IFACE="$(sed -n 's/.*tun \(utun[0-9][0-9]*\) up.*/\1/p' "$LOG" | head -1)"
    [ -n "$IFACE" ] && break
    if ! kill -0 "$GUEST_PID" 2>/dev/null; then
        echo "guest exited before creating the interface:" >&2
        tail -5 "$LOG" >&2
        exit 1
    fi
    sleep 0.5
done
# Fallback: locate the utun by the address we assigned, in case the log line
# is missing or formatted differently.
if [ -z "$IFACE" ]; then
    IFACE="$(ifconfig -a 2>/dev/null | awk '/^utun[0-9]+:/{iface=$1} /inet 10\.7\.0\.2 /{sub(":", "", iface); print iface; exit}')"
fi
[ -n "$IFACE" ] || { echo "no utun interface appeared" >&2; tail -20 "$LOG" >&2; exit 1; }
echo "tunnel interface: $IFACE"

route -n add -host "$TARGET" -interface "$IFACE"
echo "added scoped route: $TARGET -> $IFACE (default route untouched)"

BODY=""
for _ in $(seq 1 30); do
    BODY="$(curl -sS --max-time 10 "http://${TARGET}:${PORT}/" 2>/dev/null || true)"
    case "$BODY" in
        *nat-tunnel-e2e-ok*) break ;;
    esac
    sleep 1
done

case "$BODY" in
    *nat-tunnel-e2e-ok*)
        echo "PASS: fetched through the tunnel: $BODY"
        ;;
    *)
        echo "FAIL: no expected body (last response: ${BODY:-<empty>})" >&2
        tail -12 "$LOG" >&2
        exit 1
        ;;
esac

echo "--- session log ---"
grep -E "tun session ready|hole punch|punch failed" "$LOG" || tail -5 "$LOG"

AFTER="$(default_route)"
if [ "$BEFORE" != "$AFTER" ]; then
    echo "FAIL: default route changed" >&2
    exit 1
fi
