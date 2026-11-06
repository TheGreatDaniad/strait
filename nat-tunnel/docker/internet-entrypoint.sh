#!/bin/sh
# Minimal L3 "internet": connects the two WAN links and the public relay
# network. It forwards packets unchanged, which is what a real transit
# network does for two endpoints that are not behind the same L2 segment.
set -eu

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# All three networks are directly connected, so nothing needs a default
# route, and Docker's default (this container's own gateway) is wrong here.
ip route del default 2>/dev/null || true

echo "internet-entrypoint: forwarding between 172.29.0.0/24, 172.30.0.0/24 and 172.31.0.0/24"
exec sleep infinity
