#!/usr/bin/env bash
# End-to-end Docker harness for nat-tunnel.
#
# Scenarios:
#   1. direct          - net_a <-> net_b forwarding allowed
#   2. full-tunnel     - TUN mode, peer-b's default route goes through peer-a
#   3. relay-fallback  - direct forwarding dropped; relay must carry traffic
#   4. lossy           - 40 ms delay + 5% loss on the WAN, longer timeout
#
# Every scenario asserts real bytes: a small HTTP body and, except for the
# full-tunnel control-plane check, a 64 KiB download verified by sha256sum.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

IMAGE="nat-tunnel:dev"
EXPECTED_BODY="nat-tunnel-e2e-ok"
LISTEN_PORT="8080"
SCENARIO_NAMES=()
SCENARIO_RESULTS=()
CURRENT_SCENARIO=""
FAILED=0

compose() {
    docker compose "$@"
}

teardown() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
}

cleanup() {
    teardown
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

record() {
    SCENARIO_NAMES+=("$1")
    SCENARIO_RESULTS+=("$2")
}

print_summary() {
    printf '\n=== e2e summary ===\n'
    if [ "${#SCENARIO_NAMES[@]}" -eq 0 ]; then
        printf 'no scenarios ran\n'
        return 0
    fi
    local i=0
    while [ "$i" -lt "${#SCENARIO_NAMES[@]}" ]; do
        printf '%-16s %s\n' "${SCENARIO_NAMES[$i]}" "${SCENARIO_RESULTS[$i]}"
        i=$((i + 1))
    done
}

dump_logs() {
    printf '\n--- docker compose logs (%s) ---\n' "$CURRENT_SCENARIO"
    compose logs --no-color || true
}

start_stack() {
    # The image is built once below; a second build here would only add time.
    compose up -d internet router-a router-b relay peer-a peer-b
}

wait_listener() {
    local service="$1"
    local port="$2"
    local tries=60
    local i=0

    while [ "$i" -lt "$tries" ]; do
        # Check the listening socket instead of connecting: `nc -z` would open
        # a real TCP connection and burn a whole tunnel session.
        if compose exec -T "$service" sh -c "ss -ltn | grep -q ':${port} '" >/dev/null 2>&1; then
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    printf 'timed out waiting for %s to listen on 127.0.0.1:%s\n' "$service" "$port" >&2
    return 1
}

check_body() {
    local max_time="$1"
    local body

    body="$(compose exec -T peer-b curl -sS --max-time "$max_time" "http://127.0.0.1:${LISTEN_PORT}/")" || return 1

    case "$body" in
        *"$EXPECTED_BODY"*)
            return 0
            ;;
        *)
            printf 'unexpected response body: %s\n' "$body" >&2
            return 1
            ;;
    esac
}

# Kill a peer process and let it come back: the surviving side must accept the
# new session instead of rejecting its fresh counters as replays.
check_restart() {
    local max_time="$1"
    local i=0

    compose restart peer-b >/dev/null 2>&1 || return 1
    sleep 4
    while [ "$i" -lt 20 ]; do
        if check_body "$max_time"; then
            printf 'restart recovery ok\n'
            return 0
        fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

check_large() {
    local max_time="$1"
    local expected actual

    expected="$(compose exec -T peer-a sha256sum /srv/big.bin | awk '{print $1}')" || return 1
    actual="$(compose exec -T peer-b sh -c "curl -sS --max-time $max_time http://127.0.0.1:${LISTEN_PORT}/big.bin | sha256sum" | awk '{print $1}')" || return 1

    if [ "$expected" != "$actual" ]; then
        printf 'bulk checksum mismatch: expected %s got %s\n' "$expected" "$actual" >&2
        return 1
    fi
    printf 'bulk transfer ok (%s)\n' "$expected"
}

# Full-tunnel: peer-b replaces its default route with the TUN interface and
# reaches peer-a's LAN-only HTTP server. Without the tunnel that address has
# no route at all, so success proves the default path really moved.
attempt_tun() {
    CURRENT_SCENARIO="full-tunnel"
    printf '\n=== scenario: full-tunnel (TUN + default route) ===\n'
    teardown

    if ! start_stack; then
        printf 'FAIL: full-tunnel (stack did not start)\n'
        dump_logs
        record "full-tunnel" FAIL
        FAILED=1
        return 1
    fi

    local body="" route="" i=0 ok=0
    while [ "$i" -lt 40 ]; do
        if body="$(compose exec -T peer-b curl -sS --max-time 10 http://172.28.1.2:8000/ 2>/dev/null)"; then
            ok=1
            break
        fi
        i=$((i + 1))
        sleep 1
    done

    if [ "$ok" -ne 1 ]; then
        printf 'FAIL: full-tunnel (peer-a LAN service unreachable through the tunnel)\n'
        dump_logs
        record "full-tunnel" FAIL
        FAILED=1
        return 1
    fi

    case "$body" in
        *"$EXPECTED_BODY"*) ;;
        *)
            printf 'FAIL: full-tunnel (unexpected body: %s)\n' "$body"
            record "full-tunnel" FAIL
            FAILED=1
            return 1
            ;;
    esac

    route="$(compose exec -T peer-b ip route get 1.1.1.1 2>&1 || true)"
    case "$route" in
        *nat0*)
            printf 'default route goes through the tunnel: %s\n' "$route"
            ;;
        *)
            printf 'FAIL: full-tunnel (default route is not the tunnel: %s)\n' "$route"
            dump_logs
            record "full-tunnel" FAIL
            FAILED=1
            return 1
            ;;
    esac

    if ! check_large_tun 60; then
        printf 'FAIL: full-tunnel (bulk transfer)\n'
        dump_logs
        record "full-tunnel" FAIL
        FAILED=1
        return 1
    fi

    if ! leak_checks_tun; then
        printf 'FAIL: full-tunnel (leak checks)\n'
        dump_logs
        record "full-tunnel" FAIL
        FAILED=1
        return 1
    fi

    local session_logs
    session_logs="$(compose logs --no-color peer-a)"
    if [[ "$session_logs" != *"tun session ready"* ]]; then
        printf 'FAIL: full-tunnel (no tunnel session in peer-a logs)\n'
        dump_logs
        record "full-tunnel" FAIL
        FAILED=1
        return 1
    fi

    printf 'PASS: full-tunnel\n'
    record "full-tunnel" PASS
    return 0
}

# Prove that guest traffic actually leaves through the tunnel.
#
#   1. a second destination also resolves to the TUN device;
#   2. the origin sees the client as the TUN address (10.7.0.2), not the
#      guest's LAN address;
#   3. IPv6 has no routable default (fail closed, not leak);
#   4. while transferring, no application traffic appears on the physical NIC:
#      no TCP (HTTP/SSH/...), no DNS, no QUIC, no ICMP echo. ICMP unreachable
#      is excluded because it is the kernel's feedback about the tunnel's own
#      UDP socket, not application data.
leak_checks_tun() {
    local leaked

    if ! compose exec -T peer-b sh -c 'ip route get 8.8.8.8 | grep -q "dev nat0"'; then
        printf 'FAIL: 8.8.8.8 does not route through the tunnel\n' >&2
        compose exec -T peer-b ip route get 8.8.8.8 >&2 || true
        return 1
    fi

    if ! compose exec -T peer-a sh -c 'grep -q "10\.7\.0\.2" /tmp/http-server.log'; then
        printf 'FAIL: origin did not see the tunnel address as the client\n' >&2
        compose exec -T peer-a tail -5 /tmp/http-server.log >&2 || true
        return 1
    fi

    if compose exec -T peer-b sh -c 'ip -6 route show default' | grep -q ' via '; then
        printf 'FAIL: IPv6 has a routable default route (leak)\n' >&2
        return 1
    fi

    compose exec -T peer-b sh -c 'pkill tcpdump 2>/dev/null; rm -f /tmp/leak.pcap' >/dev/null 2>&1 || true
    compose exec -d peer-b sh -c 'tcpdump -ni eth0 -w /tmp/leak.pcap "tcp or (udp and port 53) or (udp and port 443) or (icmp and (icmp[icmptype] == 8 or icmp[icmptype] == 0))" 2>/dev/null'
    sleep 1
    compose exec -T peer-b sh -c 'curl -sS --max-time 30 http://172.28.1.2:8000/big.bin -o /dev/null' >/dev/null 2>&1 || true
    sleep 1
    compose exec -T peer-b sh -c 'pkill -INT tcpdump 2>/dev/null' >/dev/null 2>&1 || true
    sleep 1

    leaked="$(compose exec -T peer-b sh -c 'tcpdump -nn -r /tmp/leak.pcap 2>/dev/null | wc -l' | tr -d '[:space:]')"
    if [ "${leaked:-0}" != "0" ]; then
        printf 'FAIL: %s application packet(s) left eth0 (TCP/DNS/QUIC/ICMP echo)\n' "$leaked" >&2
        compose exec -T peer-b sh -c 'tcpdump -nn -r /tmp/leak.pcap 2>/dev/null | head -5' >&2 || true
        return 1
    fi

    printf 'no leaks: both destinations via nat0, origin saw 10.7.0.2, no TCP/DNS/QUIC/ICMP-echo on eth0, IPv6 unroutable\n'
}

check_large_tun() {
    local max_time="$1"
    local expected actual

    expected="$(compose exec -T peer-a sha256sum /srv/big.bin | awk '{print $1}')" || return 1
    actual="$(compose exec -T peer-b sh -c "curl -sS --max-time $max_time http://172.28.1.2:8000/big.bin | sha256sum" | awk '{print $1}')" || return 1

    if [ "$expected" != "$actual" ]; then
        printf 'bulk checksum mismatch: expected %s got %s\n' "$expected" "$actual" >&2
        return 1
    fi
    printf 'bulk transfer ok (%s)\n' "$expected"
}

attempt() {
    local name="$1"
    local max_time="$2"
    local expect_path="${3:-}"
    local restart="${4:-0}"

    CURRENT_SCENARIO="$name"
    printf '\n=== scenario: %s ===\n' "$name"

    teardown

    if start_stack && wait_listener peer-b "$LISTEN_PORT" && check_body "$max_time" \
        && check_large "$max_time" \
        && { [ "$restart" != "1" ] || check_restart "$max_time"; }; then
        local path_logs=""
        if [ -n "$expect_path" ]; then
            path_logs="$(compose logs --no-color peer-a)"
        fi
        if [ -n "$expect_path" ] && [[ "$path_logs" != *"session ready ($expect_path)"* ]]; then
            printf 'FAIL: %s (expected %s path, not seen in peer-a logs)\n' "$name" "$expect_path"
            dump_logs
            record "$name" FAIL
            FAILED=1
            return 1
        fi
        printf 'PASS: %s\n' "$name"
        record "$name" PASS
        return 0
    fi

    printf 'FAIL: %s\n' "$name"
    dump_logs
    record "$name" FAIL
    FAILED=1
    return 1
}

printf '=== building %s ===\n' "$IMAGE"
if ! docker build -f docker/Dockerfile -t "$IMAGE" .; then
    printf '\nFAIL: docker build\n'
    exit 1
fi

attempt "direct" 15 "direct" 1 || true
teardown

TUN=1 attempt_tun || true
teardown

BLOCK_DIRECT=1 attempt "relay-fallback" 15 "relayed" || true
teardown

DELAY_MS=40 LOSS_PCT=5 attempt "lossy" 30 || true
teardown

print_summary

if [ "$FAILED" -ne 0 ]; then
    printf '\nRESULT: FAIL\n'
    exit 1
fi

printf '\nRESULT: PASS\n'
