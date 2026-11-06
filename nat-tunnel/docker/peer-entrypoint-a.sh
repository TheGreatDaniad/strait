#!/bin/sh
# peer-a: local HTTP service reachable only from this container, exposed to
# peer-b through the tunnel's host side.
#
# TUN=1 switches to full-tunnel mode: the process owns a TUN interface and
# forwards whatever IP packets peer-b routes into it.
set -eu

ip route replace default via 172.28.1.254

mkdir -p /srv
printf 'nat-tunnel-e2e-ok\n' > /srv/index.html
# 64 KiB of zeros: multiple ARQ frames, checksummed on the other side.
dd if=/dev/zero of=/srv/big.bin bs=1024 count=64 2>/dev/null

python3 -m http.server 8000 --directory /srv >/tmp/http-server.log 2>&1 &

if [ "${TUN:-0}" = "1" ]; then
    exec nat-tunnel host \
        --relay 172.31.0.2:7000 \
        --room "${ROOM:-e2e}" \
        --key e2e-secret \
        --tun 10.7.0.1/24 \
        --tun-name nat0 \
        --max-clients "${MAX_CLIENTS:-1}"
fi

exec nat-tunnel host \
    --relay 172.31.0.2:7000 \
    --room "${ROOM:-e2e}" \
    --key e2e-secret \
    --forward 127.0.0.1:8000
