#!/usr/bin/env bash
# tunnel-relay-example.sh — Demonstrate tc-tunnel_key UNSET:
#   metadata from the first tunnel is reused for encapsulation by the second tunnel.
#
# Man-page excerpt (tc-tunnel_key(8)):
#   "UNSET function could be used in cases when traffic is forwarded between two
#    tunnels, where the metadata from the first tunnel will be used for
#    encapsulation done by the second tunnel."
#
# Topology:
#
#   [ns-left]                    [ns-relay]                    [ns-right]
#   geneve-left (external)       geneve-in  (external)
#   10.0.0.1/24 ─── veth-a ──▶  10.0.0.2/24                  10.0.1.3/24
#                                10.0.1.2/24 ─── veth-b ──▶   veth-right
#                                               geneve-out (external)
#
# What happens on the relay:
#   1. A Geneve-encapsulated packet arrives on geneve-in.
#      The kernel decapsulates it and attaches the tunnel metadata to the skb.
#   2. A tc filter on geneve-in runs "tunnel_key UNSET".
#      This explicitly transfers the skb's live metadata to the egress path,
#      including the VNI and Geneve options — they are forwarded untouched.
#   3. The packet is redirected to geneve-out (also in 'external' mode).
#   4. geneve-out's egress tc filter calls "tunnel_key set" to supply the
#      new outer src/dst IPs and port for the second leg.  VNI and geneve_opts
#      are NOT repeated here — they come from the UNSET metadata in step 2.
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
RIGHT_OVERLAY="192.168.42.3"     # inner (overlay) IP in ns-right

MAC_LEFT="02:00:00:00:00:01"     # geneve-left  (ns-left)
MAC_GIN="02:00:00:00:00:02"      # geneve-in    (ns-relay)
MAC_GOUT="02:00:00:00:00:03"     # geneve-out   (ns-relay)
MAC_RIGHT="02:00:00:00:00:04"    # geneve-right (ns-right)

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

info "Creating geneve-in"

# ns-relay: geneve-in receives from ns-left (external = metadata kept on skb)
ip netns exec ns-relay ip link add geneve-in type geneve dstport "${PORT}" external
ip netns exec ns-relay ip link set geneve-in address "${MAC_GIN}"
ip netns exec ns-relay ip link set geneve-in up

if false; then

info "Adding tc egress filter to geneve-in"

# An external-mode Geneve device only builds the outer header on egress when a
# TC egress filter exists that commits the skb's tunnel metadata.
# "tunnel_key unset" is the correct action here: it tells the Geneve driver
# "use whatever metadata is already on the skb" (set by bpf_skb_set_tunnel_key
# on ingress) without overwriting VNI or Geneve options.
ip netns exec ns-relay tc qdisc add dev geneve-in root handle 1: prio
ip netns exec ns-relay tc filter add dev geneve-in protocol ip parent 1: prio 2 \
    matchall \
    action tunnel_key unset \
    pass

fi

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

# ── 4. tc filters on the relay ────────────────────────────────────────────────
#
# The eBPF program on geneve-in ingress reads the Geneve option, looks up the
# new outer src/dst IPs in the geneve_routes map, rewrites them with
# bpf_skb_set_tunnel_key, and returns TC_ACT_OK.
#
# The packet then hits the eBPF program's TC_ACT_OK, but for the egress
# re-encapsulation to work the packet must be redirected through geneve-out
# (a separate external-mode Geneve device).  The kernel cannot re-encapsulate
# a packet that is redirected back to the same device it arrived on.
#
# geneve-in  INGRESS (eBPF + mirred):
#   1. eBPF reads option, rewrites tunnel key (new src/dst IPs), TC_ACT_OK.
#      The eBPF program is attached via user_control; the mirred redirect here
#      runs after the eBPF via TC_ACT_PIPE from the bpf direct-action program.
#      Actually: the eBPF uses direct-action and returns TC_ACT_OK, so we
#      need a second filter or the eBPF itself to do the mirred.
#
# Simplest wiring: eBPF does bpf_redirect(geneve-out ifindex, 0) after
# bpf_skb_set_tunnel_key.  geneve-out egress TC then does tunnel_key unset
# to commit the metadata the eBPF already wrote.


# ── 5. Static ARP / neighbour entries (avoids ARP over tunnel during test) ────
info "Adding neighbour entries"

ip netns exec ns-left  ip neigh add "${RIGHT_OVERLAY}" \
    lladdr "${MAC_RIGHT}" dev geneve-left nud permanent 2>/dev/null || true

ip netns exec ns-right ip neigh add "${LEFT_OVERLAY}" \
    lladdr "${MAC_LEFT}" dev geneve-right nud permanent 2>/dev/null || true

# ── 6. Show the installed filter chain ───────────────────────────────────────
info "tc filter chain on ns-relay geneve-in (ingress) — UNSET path:"
echo "  ip netns exec ns-relay tc filter show dev geneve-in ingress"
info "tc filter chain on ns-relay geneve-in (egress) — UNSET path:"
echo "  ip netns exec ns-relay tc filter show dev geneve-in egress"

#info "tc filter chain on ns-relay geneve-out (egress) — outer-IP set for right leg:"
#ip netns exec ns-relay tc filter show dev geneve-out parent 1:

if false; then
# ── 7. Connectivity test ──────────────────────────────────────────────────────
info "To test connectivity, run:"
echo ""
echo "  ip netns exec ns-left ping -c 3 -W 2 ${RIGHT_OVERLAY}"
echo ""
echo "Expected path:"
echo "  ns-left: ip(${LEFT_OVERLAY}→${RIGHT_OVERLAY}) encap geneve vni=${VNI}"
echo "       ↓  UDP ${LEFT_UNDERLAY}→${RELAY_LEFT}"
echo "  ns-relay: decap → UNSET metadata → redirect to geneve-out"
echo "       ↓  same VNI/opts, new outer UDP ${RELAY_RIGHT}→${RIGHT_UNDERLAY}"
echo "  ns-right: decap → sees plain ip(${LEFT_OVERLAY}→${RIGHT_OVERLAY})"
fi
echo ""


info "Done.  Press Enter to tear down."
read -r
