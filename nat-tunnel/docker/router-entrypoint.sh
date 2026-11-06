#!/bin/sh
# One NAT router: LAN on one side, shared WAN on the other.
#
# Required env:
#   WAN_ADDR     this router's WAN address, e.g. 172.29.0.2/24
#   WAN_GATEWAY  upstream transit address, e.g. 172.29.0.1
#   LAN_CIDR     private network to NAT, e.g. 172.28.1.0/24
#   PEER_PUBLIC  the other router's WAN IP, dropped when BLOCK_DIRECT=1
# Optional env:
#   BLOCK_DIRECT=1, DELAY_MS, LOSS_PCT
#
# NAT is NETMAP 1:1 (host part preserved): 172.28.1.2 <-> 172.29.0.2. That makes
# mapping and filtering endpoint-independent like a cone NAT, so a peer's punch
# to the relay-advertised address arrives with an unchanged source port. Plain
# MASQUERADE is symmetric and would always force the relay path.
set -eu

WAN_ADDR="${WAN_ADDR:?WAN_ADDR is required}"
WAN_GATEWAY="${WAN_GATEWAY:?WAN_GATEWAY is required}"
LAN_CIDR="${LAN_CIDR:?LAN_CIDR is required}"
PEER_PUBLIC="${PEER_PUBLIC:?PEER_PUBLIC is required}"

WAN_IP="${WAN_ADDR%/*}"
WAN_NET="${WAN_IP%.*}.0/24"

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Interface names depend on the order Docker attaches the networks, so find
# the WAN interface by its address instead of guessing eth0/eth1.
WAN_IFACE="$(ip -o -4 addr show | awk -v a="$WAN_ADDR" '$4 == a {print $2}')"
if [ -z "$WAN_IFACE" ]; then
    echo "router-entrypoint: no interface has $WAN_ADDR" >&2
    ip -o -4 addr show >&2
    exit 1
fi

# Default route out the WAN link (Docker's default points at the LAN gateway,
# which is the host bridge, not the transit network).
ip route replace default via "$WAN_GATEWAY"

# Port-preserving 1:1 NAT, both directions.
iptables -w 5 -t nat -A POSTROUTING -s "$LAN_CIDR" -o "$WAN_IFACE" -j NETMAP --to "$WAN_NET"

if [ -n "${EXTRA_LAN_HOSTS:-}" ]; then
    # Multi-host lab: map the whole WAN subnet, otherwise a second LAN host's
    # return address (e.g. 172.30.0.4) is never DNATed back.
    iptables -w 5 -t nat -A PREROUTING -i "$WAN_IFACE" -d "$WAN_GATEWAY" -j RETURN
    iptables -w 5 -t nat -A PREROUTING -i "$WAN_IFACE" -d "$WAN_NET" -j NETMAP --to "$LAN_CIDR"

    # Those extra WAN-side addresses live on this router; without proxy ARP
    # and a LAN-side /32 route, the relay's replies are never delivered.
    sysctl -w net.ipv4.conf.all.proxy_arp=1 >/dev/null
    sysctl -w "net.ipv4.conf.${WAN_IFACE}.proxy_arp=1" >/dev/null

    LAN_IFACE="$(ip -o -4 addr show | awk -v w="$WAN_IFACE" \
        '$1 ~ /^[0-9]+:$/ && $2 != "lo" && $2 != w && $3 == "inet" {print $2; exit}')"
    LAN_ADDR="$(ip -o -4 addr show dev "$LAN_IFACE" | awk 'NR == 1 {print $4}')"
    LAN_PREFIX="${LAN_ADDR%.*}"
    WAN_PREFIX="${WAN_NET%.*}"
    for h in $EXTRA_LAN_HOSTS; do
        ip route replace "${WAN_PREFIX}.${h}/32" via "${LAN_PREFIX}.${h}" dev "$LAN_IFACE"
    done
else
    # Single-host lab: keep the original port-preserving map for the router's
    # own WAN address, which is the direct-punch target.
    iptables -w 5 -t nat -A PREROUTING -i "$WAN_IFACE" -d "$WAN_IP" -j NETMAP --to "$LAN_CIDR"
fi

# Drop only direct peer traffic; the relay's WAN address stays reachable so
# the fallback path keeps working.
if [ "${BLOCK_DIRECT:-0}" = "1" ]; then
    iptables -w 5 -A FORWARD -s "$LAN_CIDR" -d "$PEER_PUBLIC" -j DROP
    iptables -w 5 -A FORWARD -s "$PEER_PUBLIC" -d "$LAN_CIDR" -j DROP
    echo "router-entrypoint: direct traffic to $PEER_PUBLIC blocked"
fi

# Optional WAN impairment (applied on one router only by compose).
if [ -n "${DELAY_MS:-}" ] || [ -n "${LOSS_PCT:-}" ]; then
    DELAY="${DELAY_MS:-0}"
    LOSS="${LOSS_PCT:-0}"
    tc qdisc replace dev "$WAN_IFACE" root netem delay "${DELAY}ms" loss "${LOSS}%"
    echo "router-entrypoint: netem on ${WAN_IFACE}: delay=${DELAY}ms loss=${LOSS}%"
fi

echo "router-entrypoint: ready (wan=${WAN_IFACE} addr=${WAN_ADDR} lan=${LAN_CIDR})"
exec sleep infinity
