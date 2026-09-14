#!/usr/bin/env bash
# create-geneve-link.sh — Create a kernel Geneve tunnel interface and assign an IPv4 address.
#
# Usage:
#   sudo ./scripts/create-geneve-link.sh [OPTIONS]
#
# Options:
#   -n <name>     Interface name          (default: geneve0)
#   -r <addr>     Remote peer IPv4        (required)
#   -v <vni>      Virtual Network ID      (default: 1)
#   -p <port>     UDP destination port    (default: 6081)
#   -a <CIDR>     Local IPv4 address/prefix to assign (required, e.g. 10.0.0.1/24)
#   -h            Show this help and exit
#
# Example:
#   sudo ./scripts/create-geneve-link.sh -r 192.168.1.2 -a 10.0.0.1/24 -v 42
#
# MAC address assignment:
#   The kernel Geneve driver generates a random MAC for each new interface.  On
#   some kernels the RNG seed produces the same value on every machine, so two
#   peers end up with identical MACs.  When that happens the receiving kernel's
#   loopback-detection logic (source MAC == own MAC) silently drops every inbound
#   frame.  This script derives a deterministic, unique MAC from the local tunnel
#   IP and the VNI so the two endpoints are always distinct:
#
#     byte 0 : 0xc2  (locally administered, unicast)
#     byte 1 : VNI bits [23:16]
#     byte 2 : VNI bits [15:8]
#     byte 3 : VNI bits [7:0]
#     byte 4 : local tunnel IP octet 3
#     byte 5 : local tunnel IP octet 4
#
# Requirements:
#   - Linux kernel with Geneve module (geneve.ko)
#   - iproute2 (ip command)
#   - Root / CAP_NET_ADMIN privileges
# ------------------------------------------------------------------------------

set -euo pipefail

# ---------- defaults ----------------------------------------------------------
IFACE="geneve0"
REMOTE=""
VNI=1
PORT=6081
ADDR=""

# ---------- MAC derivation ----------------------------------------------------
# Derive a locally-administered unicast MAC that is unique per (local-IP, VNI).
# This prevents the loopback-drop when two peers are assigned the same random MAC
# by the kernel.
#
# Arguments:
#   $1 — local tunnel CIDR  (e.g. 192.168.100.1/24)
#   $2 — VNI                (integer, 1–16777215)
# Prints the MAC in aa:bb:cc:dd:ee:ff notation.
derive_mac() {
    local cidr="$1"
    local vni="$2"

    # Strip the prefix length to get the bare IP
    local ip="${cidr%%/*}"

    # Split into octets
    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

    # Encode VNI into three bytes
    local v1=$(( (vni >> 16) & 0xFF ))
    local v2=$(( (vni >>  8) & 0xFF ))
    local v3=$(( vni         & 0xFF ))

    # 0xc2 = 1100 0010: locally administered (bit 1 set), unicast (bit 0 clear)
    printf 'c2:%02x:%02x:%02x:%02x:%02x' "$v1" "$v2" "$v3" "$o3" "$o4"
}

# ---------- helpers -----------------------------------------------------------
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[+] $*"; }

usage() {
    sed -n '/^# Usage:/,/^# -\{10\}/p' "$0" | sed 's/^# \{0,3\}//'
    exit 0
}

# ---------- argument parsing --------------------------------------------------
while getopts ":n:r:v:p:a:h" opt; do
    case $opt in
        n) IFACE="$OPTARG" ;;
        r) REMOTE="$OPTARG" ;;
        v) VNI="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        a) ADDR="$OPTARG" ;;
        h) usage ;;
        :) die "Option -$OPTARG requires an argument." ;;
        \?) die "Unknown option: -$OPTARG" ;;
    esac
done

# ---------- validation --------------------------------------------------------
[[ -n "$REMOTE" ]] || die "Remote peer address (-r) is required."
[[ -n "$ADDR"   ]] || die "Local IPv4 CIDR address (-a) is required."

# Validate remote is a dotted-quad IPv4 address
if ! [[ "$REMOTE" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    die "Remote address '$REMOTE' is not a valid IPv4 address."
fi

# Validate ADDR looks like CIDR (basic check)
if ! [[ "$ADDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    die "Address '$ADDR' must be in CIDR notation (e.g. 10.0.0.1/24)."
fi

# Validate VNI range (24-bit: 1–16777215)
if ! [[ "$VNI" =~ ^[0-9]+$ ]] || (( VNI < 1 || VNI > 16777215 )); then
    die "VNI must be an integer between 1 and 16777215."
fi

# Validate port range
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    die "Port must be an integer between 1 and 65535."
fi

# Must run as root (or with CAP_NET_ADMIN)
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root (use sudo)."
fi

# Ensure the Geneve kernel module is available
if ! modprobe geneve 2>/dev/null; then
    die "Failed to load 'geneve' kernel module — is it available on this kernel?"
fi

# ---------- tear down existing interface (idempotent) -------------------------
if ip link show "$IFACE" &>/dev/null; then
    info "Interface '$IFACE' already exists — deleting it first."
    ip link delete "$IFACE"
fi

# ---------- derive a stable MAC for this endpoint -----------------------------
MAC=$(derive_mac "$ADDR" "$VNI")
info "Derived MAC $MAC  (local=${ADDR%%/*}  vni=$VNI)"

# ---------- create the Geneve link --------------------------------------------
info "Creating Geneve interface '$IFACE'  (remote=$REMOTE  vni=$VNI  port=$PORT)"
ip link add "$IFACE" type geneve \
    remote  "$REMOTE"   \
    vni     "$VNI"      \
    dstport "$PORT"

# Override the kernel-assigned MAC with our deterministic one before bringing
# the interface up, so no traffic is ever sent with the random MAC.
ip link set "$IFACE" address "$MAC"

# ---------- assign IPv4 address and bring the interface up --------------------
info "Assigning address $ADDR to $IFACE"
ip addr add "$ADDR" dev "$IFACE"

info "Bringing $IFACE up"
ip link set "$IFACE" up

# ---------- summary -----------------------------------------------------------
echo ""
echo "Geneve interface '$IFACE' is up:"
ip -4 addr show dev "$IFACE"
ip link show dev "$IFACE"
