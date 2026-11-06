#!/usr/bin/env bash
# Verifies the host's max-clients limit with three real clients.
#
# The host is configured with MAX_CLIENTS=2. Clients 1 and 2 have lanes and must
# fetch the host's private HTTP service through their own tunnels. Client 3 has
# no lane and must never establish a session or reach the service.
#
# Requires a built image:
#   docker build -f docker/Dockerfile -t nat-tunnel:dev .
set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

EXPECTED_BODY="nat-tunnel-e2e-ok"
SERVICE="172.28.1.2:8000"
FAILED=0

compose() {
    docker compose --profile multi "$@"
}

teardown() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap teardown EXIT INT TERM

report() {
    if [ "$2" -eq 0 ]; then
        printf 'PASS: %s\n' "$1"
    else
        printf 'FAIL: %s\n' "$1"
        FAILED=1
    fi
}

if ! docker image inspect nat-tunnel:dev >/dev/null 2>&1; then
    printf 'missing nat-tunnel:dev; run: docker build -f docker/Dockerfile -t nat-tunnel:dev .\n' >&2
    exit 1
fi

teardown
# This test only needs the relay path. The extra-host NETMAP labs can learn a
# bogus direct peer after the first lane; the direct path is covered by
# scripts/e2e_docker.sh, so keep this one deterministic.
MAX_CLIENTS=2 TUN=1 NAT_TUNNEL_RELAY_ONLY=1 EXTRA_LAN_HOSTS="4 5" compose up -d internet router-a router-b relay peer-a peer-b peer-b2 peer-b3

# Wait for both lanes to carry a session.
for _ in $(seq 1 60); do
    logs="$(compose logs --no-color peer-a 2>/dev/null || true)"
    if [[ "$logs" == *"client 1 tun session ready"* && "$logs" == *"client 2 tun session ready"* ]]; then
        break
    fi
    sleep 1
done

logs="$(compose logs --no-color peer-a 2>/dev/null || true)"
if [[ "$logs" == *"client 1 tun session ready"* && "$logs" == *"client 2 tun session ready"* ]]; then
    report "two lanes established" 0
else
    report "two lanes established" 1
fi

fetch_from() {
    local service="$1"
    local attempt=0
    while [ "$attempt" -lt 30 ]; do
        if body="$(compose exec -T "$service" curl -sS --max-time 10 "http://${SERVICE}/" 2>/dev/null)"; then
            case "$body" in
                *"$EXPECTED_BODY"*) return 0 ;;
            esac
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    return 1
}

if fetch_from peer-b; then
    report "client 1 reaches the host service" 0
else
    report "client 1 reaches the host service" 1
fi

if fetch_from peer-b2; then
    report "client 2 reaches the host service" 0
else
    report "client 2 reaches the host service" 1
fi

# The third client has no lane: this must fail (and must not create a session).
if compose exec -T peer-b3 curl -sS --max-time 8 "http://${SERVICE}/" >/dev/null 2>&1; then
    report "third client is rejected" 1
else
    report "third client is rejected" 0
fi

logs="$(compose logs --no-color peer-a 2>/dev/null || true)"
if [[ "$logs" == *"client 3"* ]]; then
    report "no lane for the third client" 1
else
    report "no lane for the third client" 0
fi

printf '\n'
if [ "$FAILED" -ne 0 ]; then
    printf 'RESULT: FAIL\n'
    exit 1
fi
printf 'RESULT: PASS\n'
