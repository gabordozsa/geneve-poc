#!/usr/bin/env bash

# Topology: 4 virtual machines
#
#   [vs-1] Fyre      [vs-2] Fyre    [vs-3] IBMCloud
#   geneve0          geneve0        geneve0
#   0.0.0.0          0.0.0.0        13.120.93.41 (floating IP)
#.  ID 100           ID 200         ID 300
#
# Run as root.  Cleans up on exit.

set -euo pipefail

# Geneve overhead:
# outer ipv4 header    20 bytes
# outer udp header.     8 bytes
# Geneve base header    8 bytes
# My custom TLV option 12 bytes
# total 48 bytes
# physycal iface (ens3) mtu is 1500
MTU=1452


# ── helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }

[[ $EUID -eq 0 ]] || die "Must be run as root."
modprobe geneve 2>/dev/null || die "geneve kernel module unavailable."


cleanup() {
    info "Cleaning up ..."
    ip link delete geneve0
}
trap cleanup EXIT


# --- Site arg ----------------------------------------------------------------
[ -n $1 ] || die "Site not specified [VS1|VS2|VS3]"
[[ $1 =~ VS1|VS2|VS3 ]] || die "Site must be [VS1|VS2|VS3]"
SITE=$1

HOME_DIR=/home/gabor
[[ $SITE == VS3 ]] && HOME_DIR=/home/ubuntu
POC_DIR=$HOME_DIR/geneve-poc

# control plane to attach and configure ingress/egress ebpf tc filters
USER_CONTROL=$POC_DIR/eBPF-proxy-nat/user_control


# Launch proxies in ns-left ans ns-right
PROXY="$POC_DIR/proxy-v2"
CERTS_DIR="$POC_DIR/certs"

USE_TLS="${USE_TLS:-1}"          # set to any non-empty value to enable TLS between proxies

# proxy listen ports for remote TLS connections (forwarded to local backends)
PROXY_LPORT_TLS_1="5201"
PROXY_LPORT_TLS_2="5202"
# proxy local backend ports
BACKEND_PORT_1="5301"
BACKEND_PORT_2="5302"
# proxy listens non-TLS ports for local clients to be forwarded to remote backends
PROXY_LPORT_11=5411
PROXY_LPORT_12=5412
PROXY_LPORT_21=5421
PROXY_LPORT_22=5422

if [[ ! -x "$PROXY" ]]; then
    echo "Site $SITE error: proxy binary not found at $PROXY" >&2
    echo "       Build it first:" >&2
    echo "         gcc -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2 -g \\" >&2
    echo "             src/proxy.c -o proxy -lssl -lcrypto" >&2
    exit 1
fi

if [[ -n "$USE_TLS" ]]; then
    for f in "$CERTS_DIR/server.crt" "$CERTS_DIR/server.key"; do
        if [[ ! -f "$f" ]]; then
            echo "error: certificate file not found: $f" >&2
            echo "       Generate test certs first: ./scripts/gen-certs.sh" >&2
            exit 1
        fi
    done
fi

# ── tunables ──────────────────────────────────────────────────────────────────

# Use the same overlay IP address at each site. Also, overlay IP <-> ID hash mapping
# is different at each site. This is to mimic router network where overlay IPs are
# assigned to ID hashes independently at each site.

GENEVE_PORT=6081

declare -A ID_HASH
ID_HASH[VS1]=100
ID_HASH[VS2]=200
ID_HASH[VS3]=300

declare -A UNDERLAY
UNDERLAY[VS1]="0.0.0.0"      # private site
UNDERLAY[VS2]="0.0.0.0"      # private site
UNDERLAY[VS3]="13.120.93.41"


declare -A OVERLAY
OVERLAY[VS1]="192.168.42.100"
OVERLAY[VS2]="192.168.42.100"
OVERLAY[VS3]="192.168.42.100"


# user_ctrl args. Overlay IPs are assigned to ID hashes independently at each site.
# Each remote is: <id_hash> <overlay_ip> <nh_underlay_ip> <is_neighbor 0|1>
declare -A USER_CTRL_ARGS
NUM_REMOTE_PROXIES=2
USER_CTRL_ARGS[VS1]="geneve0 eth1 ${ID_HASH[VS1]} ${OVERLAY[VS1]} $NUM_REMOTE_PROXIES ${ID_HASH[VS2]} 192.168.42.2 ${UNDERLAY[VS3]} 0 ${ID_HASH[VS3]} 192.168.42.3  ${UNDERLAY[VS3]} 1"
USER_CTRL_ARGS[VS2]="geneve0 eth1 ${ID_HASH[VS2]} ${OVERLAY[VS2]} $NUM_REMOTE_PROXIES ${ID_HASH[VS1]} 192.168.42.21 ${UNDERLAY[VS3]} 0 ${ID_HASH[VS3]} 192.168.42.23  ${UNDERLAY[VS3]} 1"
USER_CTRL_ARGS[VS3]="geneve0 ens3 ${ID_HASH[VS3]} ${OVERLAY[VS3]} $NUM_REMOTE_PROXIES ${ID_HASH[VS1]} 192.168.42.31 ${UNDERLAY[VS1]} 1 ${ID_HASH[VS2]} 192.168.42.32  ${UNDERLAY[VS2]} 1"


# ── 3. Overlay: Geneve interfaces ─────────────────────────────────────────────
info "Creating geneve0 at site $SITE"

# ns-left: external Geneve
ip link add geneve0 type geneve dstport $GENEVE_PORT  innerprotoinherit external
ip addr add "${OVERLAY[$SITE]}/24" dev geneve0
ip link set dev geneve0 mtu $MTU
ip link set geneve0 up

# Attach ebpf filters
pushd $(dirname $USER_CONTROL) >/dev/null

info "Attaching ebpf filters to geneve0 at $SITE "
$USER_CONTROL ${USER_CTRL_ARGS[$SITE]} &
uc_pid=$!
sleep 1

popd >/dev/null

# ---------------------------------------------------------------------------
# 3. Print proxy commands
# ---------------------------------------------------------------------------
[[  -n "$USE_TLS" ]] && TLS="-S"
PROXY_ARGS="-c $PROXY_LPORT_TLS_1$TLS:0.0.0.0:$BACKEND_PORT_1 -c $PROXY_LPORT_TLS_2$TLS:0.0.0.0:$BACKEND_PORT_2"
case $SITE in
    VS3)
        PROXY_ARGS+=" -c $PROXY_LPORT_11:192.168.42.31:$PROXY_LPORT_TLS_1$TLS -c $PROXY_LPORT_12:192.168.42.31:$PROXY_LPORT_TLS_2$TLS"
        PROXY_ARGS+=" -c $PROXY_LPORT_21:192.168.42.32:$PROXY_LPORT_TLS_1$TLS -c $PROXY_LPORT_22:192.168.42.32:$PROXY_LPORT_TLS_2$TLS"
        PROXY_CMD="$PROXY $PROXY_ARGS"
        ;;
    *)
        PROXY_CMD="$PROXY $PROXY_ARGS"
        ;;
esac

echo ""
echo "==> Setup complete"


echo "Start the HTTP servers:"
echo ""
echo "    mkdir -p $HOME_DIR/server_1; echo \"<html><body>Hello from $SITE server_1</body><html>\" > $HOME_DIR/server_1/index.htm"
echo "    python3 -m http.server $BACKEND_PORT_1 --directory $HOME_DIR/server_1"
echo ""
echo "    mkdir -p $HOME_DIR/server_2; echo \"<html><body>Hello from $SITE server_2</body><html>\" > $HOME_DIR/server_2/index.htm"
echo "    python3 -m http.server $BACKEND_PORT_2 --directory $HOME_DIR/server_2"
echo ""
echo ""
echo "Start proxy:"
echo ""
echo "    $PROXY_CMD"
echo ""

info "Done.  Press Ctrl-C to tear down."

# Only Ctrl-C (SIGINT) from the user triggers teardown: forward it to user_control.
trap 'kill -INT $uc_pid 2>/dev/null || true' INT

# The first wait is interrupted by the trapped SIGINT; the second one waits for
# user_control to actually finish detaching its filters before cleanup() runs.
wait $uc_pid || true
wait $uc_pid || true