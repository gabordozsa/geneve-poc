#!/usr/bin/env bash

# Topology: 4 virtual machines
#
#   [vs-1] Fyre      [vs-2] Fyre    [vs-3] IBMCloud
#   geneve0          geneve0        geneve0
#   0.0.0.0          0.0.0.0        13.121.90.155 (floating IP)
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
MTU=1552


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

POC_DIR=/home/ubuntu/geneve-poc
[[ $SITE == VS3 ]] ||POC_DIR=/home/gabor/geneve-poc

# control plane to attach and configure ingress/egress ebpf tc filters
USER_CONTROL=$POC_DIR/eBPF-proxy-nat/user_control
 

# Launch proxies in ns-left ans ns-right
PROXY="$POC_DIR/proxy"
CERTS_DIR="$POC_DIR/certs"

USE_TLS="${USE_TLS:-1}"          # set to any non-empty value to enable TLS between proxies

PROXY_PORT="5201"   # port the two proxy instances communicate on
BACKEND_PORT="5301"    # server port 

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
UNDERLAY[VS1]="0.0.0.0"
UNDERLAY[VS2]="0.0.0.0"
UNDERLAY[VS3]="13.121.90.155"


declare -A OVERLAY
OVERLAY[VS1]="192.168.42.100"
OVERLAY[VS2]="192.168.42.100"
OVERLAY[VS3]="192.168.42.100"


# user_ctrl args. Overlay IPs are assigned to ID hashes independently at each site.
declare -A USER_CTRL_ARGS
NUM_REMOTE_PROXIES=2
USER_CTRL_ARGS[VS1]="geneve0 eth1 ${ID_HASH[VS1]} ${OVERLAY[VS1]} $NUM_REMOTE_PROXIES ${ID_HASH[VS2]} 192.168.42.2 ${UNDERLAY[VS3]} ${ID_HASH[VS3]} 192.168.42.3  ${UNDERLAY[VS3]}"
USER_CTRL_ARGS[VS2]="geneve0 eth1 ${ID_HASH[VS2]} ${OVERLAY[VS2]} $NUM_REMOTE_PROXIES ${ID_HASH[VS1]} 192.168.42.21 ${UNDERLAY[VS3]} ${ID_HASH[VS3]} 192.168.42.23  ${UNDERLAY[VS3]}"
USER_CTRL_ARGS[VS3]="geneve0 ens3 ${ID_HASH[VS3]} ${OVERLAY[VS3]} $NUM_REMOTE_PROXIES ${ID_HASH[VS1]} 192.168.42.31 ${UNDERLAY[VS1]} ${ID_HASH[VS2]} 192.168.42.32  ${UNDERLAY[VS2]}"


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
# Server-side proxy at VS4
if [[ -n "$USE_TLS" ]]; then
    SERVER_PROXY_CMD=("$PROXY" -l "$PROXY_PORT" -r "127.0.0.1" -p "$BACKEND_PORT" -L -D -n server)
else
    SERVER_PROXY_CMD=("$PROXY" -l "$PROXY_PORT" -r "127.0.0.1" -p "$BACKEND_PORT" -D -n server)
fi

# Client-side proxy : connect to VS4 (which is locally identified by 92.168.42.4) via Geneve hops VS1 -> VS2 ->VS3 -> VS4
if [[ -n "$USE_TLS" ]]; then
    CLIENT_PROXY_CMD=("$PROXY" -l "$PROXY_PORT" -r 192.168.42.4 -p "$PROXY_PORT" -R -n client)
else
    CLIENT_PROXY_CMD=("$PROXY" -l "$PROXY_PORT" -r 192.168.42.4 -p "$PROXY_PORT" -n client)
fi

echo ""
echo "==> Setup complete"

if [[ $SITE = "VS3" ]]; then
    echo ""
    echo "Start the server-side proxy in a separate terminal:"
    echo ""
    printf '    '
    printf '%q ' "${SERVER_PROXY_CMD[@]}"
    echo ""
    echo ""
    echo "Start the HTTP server in the server namespace:"
    echo ""
    echo "    python3 -m http.server $BACKEND_PORT --directory $CERTS_DIR"
    echo ""
elif [[ $SITE = "VS1" ]]; then
    echo ""
    echo "Start the client-side proxy in a separate terminal:"
    echo ""
    printf '    '
    printf '%q ' "${CLIENT_PROXY_CMD[@]}"
    echo ""
    echo "Test the web server through the proxy chain:"
    echo ""
    echo "    curl http://127.0.0.1:$PROXY_PORT/"
    echo ""
fi

info "Done.  Press Enter to tear down."
read -r

kill $uc_pid
wait $uc_pid