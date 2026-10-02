#!/usr/bin/env bash

# Topology:
#
#   [ns-left]                    [ns-relay]                    [ns-right]
#   geneve-left (external)       geneve-rel  (external)
#   10.0.0.1/24 ─── veth-a ──▶  10.0.0.2/24                  10.0.1.3/24
#                                10.0.1.2/24 ─── veth-b ──▶   veth-right
#
# Run as root.  Cleans up on exit.

set -euo pipefail

# ── tunables ──────────────────────────────────────────────────────────────────
VNI=42
PORT=6081
GENEVE_OPT_LEFT="0101:2A:00000064"   # class:type:data — carried verbatim through relay, data : 100
GENEVE_OPT_RIGHT="0101:2A:000000C8"   # class:type:data — carried verbatim through relay, data : 200

LEFT_UNDERLAY="10.0.0.1"         # ns-left  veth address
RELAY_LEFT="10.0.0.2"            # ns-relay veth-a address (left leg underlay)
RELAY_RIGHT="10.0.1.2"           # ns-relay veth-b address (right leg underlay)
RIGHT_UNDERLAY="10.0.1.3"        # ns-right veth address

LEFT_OVERLAY="192.168.42.1"      # inner (overlay) IP in ns-left
RELAY_OVERLAY="192.168.42.2"
RIGHT_OVERLAY="192.168.42.3"     # inner (overlay) IP in ns-right

MAC_LEFT="02:00:00:00:00:01"     # geneve-left  (ns-left)
MAC_RELAY="02:00:00:00:00:02"      # geneve-rel    (ns-relay)
MAC_RIGHT="02:00:00:00:00:03"    # geneve-right (ns-right)

# ── helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }

[[ $EUID -eq 0 ]] || die "Must be run as root."
modprobe geneve 2>/dev/null || die "geneve kernel module unavailable."

cleanup() {
    info "Cleaning up ..."
    ip netns del ns-left  2>/dev/null || true
    ip netns del ns-relay 2>/dev/null || true
    ip netns del ns-right 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Network namespaces ─────────────────────────────────────────────────────
info "Creating namespaces: ns-left, ns-relay, ns-right"
ip netns add ns-left
ip netns add ns-relay
ip netns add ns-right

# ── 2. Underlay: veth pairs ───────────────────────────────────────────────────
info "Creating underlay veth pairs"

# left leg
ip link add veth-la type veth peer name veth-ra
ip link set veth-la netns ns-left
ip link set veth-ra netns ns-relay

ip netns exec ns-left  ip addr add "${LEFT_UNDERLAY}/24"  dev veth-la
ip netns exec ns-left  ip link set veth-la up
ip netns exec ns-left  ip link set lo up

ip netns exec ns-relay ip addr add "${RELAY_LEFT}/24"     dev veth-ra
ip netns exec ns-relay ip link set veth-ra up

# right leg
ip link add veth-rb type veth peer name veth-rc
ip link set veth-rb netns ns-relay
ip link set veth-rc netns ns-right

ip netns exec ns-relay ip addr add "${RELAY_RIGHT}/24"    dev veth-rb
ip netns exec ns-relay ip link set veth-rb up
ip netns exec ns-relay ip link set lo up

ip netns exec ns-right ip addr add "${RIGHT_UNDERLAY}/24" dev veth-rc
ip netns exec ns-right ip link set veth-rc up
ip netns exec ns-right ip link set lo up

# ── 3. Overlay: Geneve interfaces ─────────────────────────────────────────────
info "Creating geneve-left"

# ns-left: external Geneve — tc egress filter supplies VNI, outer IPs, and
# geneve_opts so that GENEVE_OPT is actually carried in the tunnel header.
ip netns exec ns-left ip link add geneve-left type geneve dstport "${PORT}" external
ip netns exec ns-left ip link set geneve-left address "${MAC_LEFT}"
ip netns exec ns-left ip addr add "${LEFT_OVERLAY}/24" dev geneve-left
ip netns exec ns-left ip link set geneve-left up

info "Adding tc filter to geneve-left"

ip netns exec ns-left tc qdisc add dev geneve-left root handle 1: prio
ip netns exec ns-left tc filter add dev geneve-left protocol ip parent 1: \
    matchall \
    action tunnel_key set \
        src_ip  "${LEFT_UNDERLAY}"  \
        dst_ip  "${RELAY_LEFT}"     \
        dst_port "${PORT}"          \
        id      "${VNI}"            \
        ttl     3                  \
        geneve_opts "${GENEVE_OPT_LEFT}" \
    pass

info "Creating geneve-rel"

# ns-relay: geneve-rel 
ip netns exec ns-relay ip link add geneve-rel type geneve dstport "${PORT}" external
ip netns exec ns-relay ip link set geneve-rel address "${MAC_RELAY}"
ip netns exec ns-relay ip addr add "${RELAY_OVERLAY}/24" dev geneve-rel
ip netns exec ns-relay ip link set geneve-rel up

info "Adding geneve-right"

# ns-right: standard Geneve — decapsulates packets arriving from relay's right leg
ip netns exec ns-right ip link add geneve-right type geneve dstport "${PORT}" external
ip netns exec ns-right ip link set geneve-right address "${MAC_RIGHT}"
ip netns exec ns-right ip addr add "${RIGHT_OVERLAY}/24" dev geneve-right
ip netns exec ns-right ip link set geneve-right up

info "Adding tc filter to geneve-right"

ip netns exec ns-right tc qdisc add dev geneve-right root handle 1: prio
ip netns exec ns-right tc filter add dev geneve-right protocol ip parent 1: \
    matchall \
    action tunnel_key set \
        src_ip  "${RIGHT_UNDERLAY}"  \
        dst_ip  "${RELAY_RIGHT}"     \
        dst_port "${PORT}"          \
        id      "${VNI}"            \
        ttl     3                   \
        geneve_opts "${GENEVE_OPT_RIGHT}" \
    pass

# ── 5. Static ARP / neighbour entries (avoids ARP over tunnel during test) ────
info "Adding neighbour entries"

# ns-left
ip netns exec ns-left ip neigh add "${RIGHT_OVERLAY}" \
    lladdr "${MAC_RIGHT}" dev geneve-left nud permanent

ip netns exec ns-left ip neigh add "${RELAY_OVERLAY}" \
    lladdr "${MAC_RELAY}" dev geneve-left nud permanent

# ns-relay
ip netns exec ns-relay ip neigh add "${RIGHT_OVERLAY}" \
    lladdr "${MAC_RIGHT}" dev geneve-rel nud permanent

ip netns exec ns-relay  ip neigh add "${LEFT_OVERLAY}" \
    lladdr "${MAC_LEFT}" dev geneve-rel nud permanent

# ns-right
ip netns exec ns-right ip neigh add "${LEFT_OVERLAY}" \
    lladdr "${MAC_LEFT}" dev geneve-right nud permanent

ip netns exec ns-right ip neigh add "${RELAY_OVERLAY}" \
    lladdr "${MAC_RELAY}" dev geneve-right nud permanent

# ── 6. Show the installed filter chain ───────────────────────────────────────
info "tc filter chain on ns-relay geneve-rel (ingress) — UNSET path:"
echo "  ip netns exec ns-relay tc filter show dev geneve-rel ingress"
info "tc filter chain on ns-relay geneve-rel (egress) — UNSET path:"
echo "  ip netns exec ns-relay tc filter show dev geneve-rel egress"

echo ""
info "Done.  Press Enter to tear down."
read -r
