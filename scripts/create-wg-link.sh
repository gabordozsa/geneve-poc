#!/usr/bin/env bash
set -eu

SUDO=sudo
#SUDO=echo

usage () {
    echo "$1, usage: $0 [-c] -l <local_overlay_ip>  -k <peer_public_key> -p <peer_overlay_ip> [-u <peer_underlay_ip>]"
    exit 1
}

(($# > 3)) || usage "argc $#" 

CREATE_KEYS=""
PEER_UNDERLAY_IP=""
PEER_ENDPOINT=""

while getopts ":cl:k:p:u" opt; do
    case $opt in
        c) CREATE_KEYS=1 ;;
        l) LOCAL_OVERLAY_IP="$OPTARG" ;;
        k) PEER_PUBKEY="$OPTARG" ;;
        p) PEER_OVERLAY_IP="$OPTARG" ;;
        u) PEER_UNDERLAY_IP=1 ;;
        *) usage "unknown arg" ;;
    esac
done

[[ -n $PEER_UNDERLAY_IP ]] && PEER_UNDERLAY_IP=${@:$OPTIND:1}

echo "CREATE_KEYS:$CREATE_KEYS LOCAL_OVERLAY_IP:$LOCAL_OVERLAY_IP PEER_PUBKEY:$PEER_PUBKEY PEER_OVERLAY_IP:$PEER_OVERLAY_IP PEER_UNDERLAY_IP:$PEER_UNDERLAY_IP" 

# Generate keys if they don't exist yet. Apparmor on Ubuntu requires to use /etc/wireguard dir
KEY_DIR=/etc/wireguard
if [[ -n $CREATE_KEYS ]] && ! sudo test -f $KEY_DIR/privatekey; then
    $SUDO touch $KEY_DIR/privatekey
    $SUDO chmod 0600 $KEY_DIR/privatekey
    wg genkey | sudo tee $KEY_DIR/privatekey
    $SUDO cat $KEY_DIR/privatekey | wg pubkey | sudo tee $KEY_DIR/publickey
fi

[[ -n $PEER_PUBKEY ]] || { "Peer public key must be set - exiting"; exit 1; }

# Delete iface if it exists
$SUDO ip link del dev wg0 2>/dev/null

$SUDO ip link add dev wg0 type wireguard
$SUDO ip address add dev wg0 $LOCAL_OVERLAY_IP/24
$SUDO wg set wg0 private-key $KEY_DIR/privatekey listen-port 51820

[[ -n $PEER_UNDERLAY_IP ]] && PEER_ENDPOINT="endpoint $PEER_UNDERLAY_IP:51820"
$SUDO wg set wg0 peer "$PEER_PUBKEY" allowed-ips $PEER_OVERLAY_IP/32 $PEER_ENDPOINT

$SUDO ip link set up dev wg0

$SUDO wg show wg0