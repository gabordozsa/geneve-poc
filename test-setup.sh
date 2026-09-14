#!/usr/bin/env bash
# test-setup.sh — set up two network namespaces connected by a veth pair and
#                 start a proxy instance in each, optionally linked by TLS.
#
# Topology (TLS mode):
#
#   [client ns]                                    [server ns]
#   curl http://127.0.0.1:5201                     python3 -m http.server :5301
#       ↓ plain TCP :5201                          ↑ plain TCP :5301 (per request)
#   proxy -l 5201 -r 10.0.0.2 -p 5201 -R -F       proxy -l 5201 -r 127.0.0.1 -p 5301 -L -S -D
#       ↓ TLS (permanent)                          ↑ TLS (permanent inter-proxy link)
#   veth-client 10.0.0.1 ←──────────────────────── veth-server 10.0.0.2
#
# Topology (plain mode, USE_TLS unset):
#
#   [client ns]                                    [server ns]
#   curl http://127.0.0.1:5201                     python3 -m http.server :5301
#       ↓ plain TCP :5201                          ↑ plain TCP :5301 (per request)
#   proxy -l 5201 -r 10.0.0.2 -p 5201 -F          proxy -l 5201 -r 127.0.0.1 -p 5301 -S -D
#       ↓ plain TCP (permanent)                    ↑ plain TCP (permanent inter-proxy link)
#   veth-client 10.0.0.1 ←──────────────────────── veth-server 10.0.0.2
#
# Connection lifetime:
#   client ↔ server proxy: permanent (created at startup, lives until a proxy stops)
#   server proxy ↔ httpd:  per-request (opened on first data, closed on DISCONNECT)
#
# Startup order:
#   1. python3 http.server in 'server' ns on HTTP_PORT (5301)
#   2. server-side proxy: listens on PROXY_PORT (5201), no backend connection yet (-D)
#   3. client-side proxy: connects to server proxy (permanent), listens plain on PROXY_PORT
#   4. curl from 'client' ns to 127.0.0.1:PROXY_PORT
#
# Environment variables:
#   USE_TLS=1    Enable TLS between the two proxy instances (default: off)
#
# Requires: ip(8), iproute2, python3, and the ./proxy binary.
# Run as root (network namespace creation requires CAP_SYS_ADMIN).

set -euo pipefail

IPERF="/home/ubuntu/iperf2/src/iperf"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY="$SCRIPT_DIR/proxy"
CERTS_DIR="$SCRIPT_DIR/certs"
USE_TLS="${USE_TLS:-1}"          # set to any non-empty value to enable TLS between proxies

CLIENT_NS="client"
SERVER_NS="server"
VETH_CLIENT="veth-client"
VETH_SERVER="veth-server"
CLIENT_IP="10.0.0.1"
SERVER_IP="10.0.0.2"
PREFIX_LEN="24"
PROXY_PORT="5201"   # port the two proxy instances communicate on
HTTP_PORT="5301"    # port python http.server listens on inside the server namespace

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "error: this script must be run as root" >&2
    exit 1
fi

if [[ ! -x "$PROXY" ]]; then
    echo "error: proxy binary not found at $PROXY" >&2
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

# ---------------------------------------------------------------------------
# Cleanup helper — removes namespaces and veth pair on exit or error
# ---------------------------------------------------------------------------
cleanup() {
    echo "==> Cleaning up namespaces and veth pair ..."
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    # Deleting the namespace also removes the veth peer, but be explicit:
    ip link del "$VETH_CLIENT" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Create network namespaces
# ---------------------------------------------------------------------------
echo "==> Creating network namespaces: $CLIENT_NS, $SERVER_NS"
ip netns add "$CLIENT_NS"
ip netns add "$SERVER_NS"

# ---------------------------------------------------------------------------
# 2. Create veth pair and assign one end to each namespace
# ---------------------------------------------------------------------------
echo "==> Creating veth pair: $VETH_CLIENT <-> $VETH_SERVER"
ip link add "$VETH_CLIENT" type veth peer name "$VETH_SERVER"
ip link set "$VETH_CLIENT" netns "$CLIENT_NS"
ip link set "$VETH_SERVER" netns "$SERVER_NS"

# Assign IP addresses and bring interfaces up
ip netns exec "$CLIENT_NS" ip addr add "${CLIENT_IP}/${PREFIX_LEN}" dev "$VETH_CLIENT"
ip netns exec "$CLIENT_NS" ip link set "$VETH_CLIENT" up
ip netns exec "$CLIENT_NS" ip link set lo up

ip netns exec "$SERVER_NS" ip addr add "${SERVER_IP}/${PREFIX_LEN}" dev "$VETH_SERVER"
ip netns exec "$SERVER_NS" ip link set "$VETH_SERVER" up
ip netns exec "$SERVER_NS" ip link set lo up

# ---------------------------------------------------------------------------
# 3. Start proxy in the server namespace
# ---------------------------------------------------------------------------
# Server-side proxy: receives framed data from the client-side proxy (-S to strip
# the control byte from upstream data), closes the upstream connection on DISCONNECT
# frames (-C), and forwards plain data to the HTTP server.
if [[ -n "$USE_TLS" ]]; then
    echo "==> Starting proxy in '$SERVER_NS' namespace (TLS listener :$PROXY_PORT -> 127.0.0.1:$HTTP_PORT plain, -S -D)"
    ip netns exec "$SERVER_NS" \
        "$PROXY" -l "$PROXY_PORT" -r "127.0.0.1" -p "$HTTP_PORT" -L -S -D -n server &
else
    echo "==> Starting proxy in '$SERVER_NS' namespace (plain :$PROXY_PORT -> 127.0.0.1:$HTTP_PORT, -S -D)"
    ip netns exec "$SERVER_NS" \
        "$PROXY" -l "$PROXY_PORT" -r "127.0.0.1" -p "$HTTP_PORT" -S -D -n server &
fi
SERVER_PROXY_PID=$!

# Give the server-side proxy a moment to bind before the client connects.
sleep 0.3

# ---------------------------------------------------------------------------
# 4. Start proxy in the client namespace
# ---------------------------------------------------------------------------
# Client-side proxy: accepts plain data from curl, frames it toward the
# server-side proxy (-F), optionally over TLS (-R).
if [[ -n "$USE_TLS" ]]; then
    echo "==> Starting proxy in '$CLIENT_NS' namespace (plain listener :$PROXY_PORT -> $SERVER_IP:$PROXY_PORT TLS, -F)"
    ip netns exec "$CLIENT_NS" \
        "$PROXY" -l "$PROXY_PORT" -r "$SERVER_IP" -p "$PROXY_PORT" -R -F -n client &
else
    echo "==> Starting proxy in '$CLIENT_NS' namespace (plain :$PROXY_PORT -> $SERVER_IP:$PROXY_PORT, -F)"
    ip netns exec "$CLIENT_NS" \
        "$PROXY" -l "$PROXY_PORT" -r "$SERVER_IP" -p "$PROXY_PORT" -F -n client &
fi
CLIENT_PROXY_PID=$!

echo ""
echo "==> Setup complete (TLS between proxies: ${USE_TLS:+yes}${USE_TLS:-no})."
echo "    Server-side proxy PID : $SERVER_PROXY_PID"
echo "    Client-side proxy PID : $CLIENT_PROXY_PID"
echo ""
echo "Start the HTTP server in the server namespace:"
echo ""
echo "    sudo ip netns exec $SERVER_NS python3 -m http.server $HTTP_PORT --directory $SCRIPT_DIR"
echo ""
echo "Test the web server through the proxy chain:"
echo ""
echo "    sudo ip netns exec $CLIENT_NS curl http://127.0.0.1:$PROXY_PORT/"
echo ""
echo "Run iperf server in the server namespace (listening on HTTP_PORT, where the server proxy forwards to):"
echo ""
echo "    sudo ip netns exec $SERVER_NS $IPERF -s -p $HTTP_PORT"
echo ""
echo "Run iperf client from the client namespace (connecting through the client proxy):"
echo ""
echo "    sudo ip netns exec $CLIENT_NS $IPERF -c 127.0.0.1 -p $PROXY_PORT"
echo ""
echo "Press Ctrl-C to tear down the namespaces and stop the proxies."

# ---------------------------------------------------------------------------
# 6. Wait until the user interrupts
# ---------------------------------------------------------------------------
wait
