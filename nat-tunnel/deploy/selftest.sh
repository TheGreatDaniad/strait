#!/usr/bin/env bash
# Offline self-test for deploy.sh: stages everything under a temp DEST_ROOT, touches nothing real.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB=0123456789abcdef0123456789abcdef
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
printf '#!/bin/sh\n' > "$T/fakebin"; chmod +x "$T/fakebin"
export DEST_ROOT="$T/root" SYSTEMCTL=echo UFW=echo
D() { bash "$HERE/deploy.sh" --bin "$T/fakebin" "$@"; }
fail=0
ok() { if [ "$2" = 0 ]; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
ENVF="$DEST_ROOT/etc/strait/host.env"

D --dry-run > "$T/dry.out" 2>&1; ok "dry-run exits 0 and writes no host.env" $([ ! -e "$ENVF" ] && echo 0 || echo 1)
D > "$T/run1.out" 2>&1; ok "first run exits 0" $?
key="$(grep -o 'STRAIT_INVITE=STRAIT2|[0-9a-f]*' "$ENVF" | cut -d'|' -f2)"
[[ "$key" =~ ^[0-9a-f]{32}$ ]]; ok "key is 32 hex" $?
[ "$key" != "$LAB" ]; ok "key is not the lab key" $?
[ "$(stat -f %Lp "$ENVF" 2>/dev/null || stat -c %a "$ENVF")" = 600 ]; ok "host.env is 0600" $?
inv="$(grep '^STRAIT2|' "$T/run1.out" | tail -1)"
[[ "$inv" =~ ^STRAIT2\|[0-9a-f]{32}\|[0-9.]+:[0-9]+$ ]]; ok "printed invite matches STRAIT2|key|host:port" $?
grep -q -- '--userspace' "$ENVF" && grep -q -- '--max-clients' "$ENVF"; ok "default host args are userspace + max-clients" $?
D > "$T/run2.out" 2>&1; key2="$(grep -o 'STRAIT2|[0-9a-f]*' "$ENVF" | head -1 | cut -d'|' -f2)"
[ "$key" = "$key2" ]; ok "second run keeps the key" $?
D --rotate > /dev/null 2>&1; key3="$(grep -o 'STRAIT2|[0-9a-f]*' "$ENVF" | head -1 | cut -d'|' -f2)"
[ "$key3" != "$key" ] && [ "$key3" != "$LAB" ]; ok "--rotate replaces the key" $?
printf 'STRAIT_INVITE=STRAIT2|%s|1.2.3.4:7100\n' "$LAB" > "$ENVF"
D > /dev/null 2>&1; ok "lab key in host.env refused without --rotate" $([ $? -ne 0 ] && echo 0 || echo 1)
grep -q "$LAB" "$ENVF"; ok "refusal left file untouched" $?
D --rotate > /dev/null 2>&1; ! grep -q "$LAB" "$ENVF"; ok "--rotate replaces the lab key" $?
D --print-units | grep -q 'ExecStart=.*host --invite'; ok "--print-units prints the host unit" $?
! D --print-units | grep -q -- '--forward 127.0.0.1:22'; ok "no placeholder --forward in units" $?
! grep -q '^IPAddressDeny' "$HERE/strait-host.service"; ok "host unit sets no IPAddressDeny" $?
for f in deploy.sh selftest.sh verify.sh; do bash -n "$HERE/$f"; ok "bash -n $f" $?; done
if command -v shellcheck >/dev/null; then shellcheck "$HERE"/*.sh; ok shellcheck $?; else echo "skip shellcheck (not installed)"; fi
echo "invite parse: regex only (the CLI has no parse-only path; guest --invite would dial)"
exit $fail
