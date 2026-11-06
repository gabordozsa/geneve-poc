#!/usr/bin/env bash

set -eu

# Set up wg tunnel (linear topology) between two virtual servers: vs1 -> vs4

VS=$1

#SUDO=echo
SUDO=sudo

SCRIPT_DIR="/home/ubuntu"

declare -A UNDERLAY
UNDERLAY[VS1]="10.251.64.6"
#UNDERLAY[VS2]="10.251.0.5"
#UNDERLAY[VS3]="10.251.64.4"
UNDERLAY[VS4]="10.251.0.4"

declare -A OVERLAY
OVERLAY[VS1]="192.168.100.1"
#OVERLAY[VS2]="192.168.100.2"
#OVERLAY[VS3]="192.168.100.3"
OVERLAY[VS4]="192.168.100.4"

declare -A PUBKEY
PUBKEY[VS1]="7w5pNa8olOR4KFIMdagnqTxyL8iqD0lxRYUkbrNvyWw="
#PUBKEY[VS2]="GzB+IICfiioItbLy/ht5zhCt9q/iVlQtSvk4klMs9xw="
#PUBKEY[VS3]="87+NymzZcB3wQRcwDPmhIQIRLodzM/NRkA7NLL0UdFw="
PUBKEY[VS4]="8oe4AgTONIrlVPIbb/wXmaXccLvZdnoZd9WCX0exLS8="

declare -A WG_CREATE_ARGS
declare -A EXTRA_CMD

# VS1
WG_CREATE_ARGS[VS1]=" -l ${OVERLAY[VS1]} -k "${PUBKEY[VS4]}" -p ${OVERLAY[VS4]} -u ${UNDERLAY[VS4]}"
EXTRA_CMD[VS1]=""
# VS2
#WG_CREATE_ARGS[VS2]=" -l ${OVERLAY[VS2]} -k ${PUBKEY[VS3]} -p ${OVERLAY[VS3]} -u ${UNDERLAY[VS3]}"
#EXTRA_CMD[VS2]="$SUDO wg set wg0 peer "${PUBKEY[VS1]}" allowed-ips ${OVERLAY[VS1]}/32"
# VS3
#WG_CREATE_ARGS[VS3]=" -l ${OVERLAY[VS3]} -k ${PUBKEY[VS4]} -p ${OVERLAY[VS4]} -u ${UNDERLAY[VS4]}"
#EXTRA_CMD[VS3]="$SUDO wg set wg0 peer ${PUBKEY[VS2]} allowed-ips ${OVERLAY[VS2]}/32"
# VS4
WG_CREATE_ARGS[VS4]=" -l ${OVERLAY[VS4]} -k ${PUBKEY[VS1]} -p ${OVERLAY[VS1]}"
EXTRA_CMD[VS4]=""

CMD="$SCRIPT_DIR/create-wg-link.sh ${WG_CREATE_ARGS[$VS]}"
echo $CMD
eval $CMD
[[ -n ${EXTRA_CMD[$VS]} ]] && { echo ${EXTRA_CMD[$VS]}; eval  ${EXTRA_CMD[$VS]}; }