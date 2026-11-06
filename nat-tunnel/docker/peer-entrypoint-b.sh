#!/bin/sh
# peer-b: guest side.
#
# Default mode forwards TCP connections accepted on 127.0.0.1:8080.
# TUN=1 switches to full-tunnel mode: the default route moves to the tunnel,
# while the WAN networks stay on the physical path so the tunnel's own UDP
# packets do not recurse into it.
set -eu

ip route replace default via 172.28.2.254

if [ "${TUN:-0}" = "1" ]; then
    exec nat-tunnel guest \
        --relay 172.31.0.2:7000 \
        --room "${ROOM:-e2e}" \
        --key e2e-secret \
        --tun "${TUN_ADDR:-10.7.0.2/24}" \
        --tun-name nat0 \
        --tun-default-route "${GATEWAY:-10.7.0.1}" \
        --tun-bypass 172.29.0.2/32 \
        --tun-bypass 172.31.0.2/32
fi

exec nat-tunnel guest \
    --relay 172.31.0.2:7000 \
    --room "${ROOM:-e2e}" \
    --key e2e-secret \
    --listen 127.0.0.1:8080
