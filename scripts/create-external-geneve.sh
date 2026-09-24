#!/usr/bin/env bash

NAME=geneve0
ADDR=192.168.200.2/24

UDP_SRC_IP=10.0.0.2
UDP_DST_IP=10.0.0.1
PORT=6081
VNI=1

#if false; then

ip link add name $NAME type geneve dstport 0 external
ip link set $NAME up
ip addr add ${ADDR} dev $NAME

#fi

# egress
tc qdisc add dev $NAME root handle 1: prio
tc filter add dev $NAME protocol ip parent 1: \
    matchall \
    action tunnel_key set \
    src_ip $UDP_SRC_IP \
    dst_ip $UDP_DST_IP \
    dst_port $PORT \
    id $VNI \
    geneve_opts 0FF01:80:123456789 \
    pass


# Add ARP record for the remote geneve address
#arp -s -i geneve0 192.168.200.1 2e:0e:d3:62:e4:a1

# Print the filter action
#ip netns exec client tc filter show dev geneve0
