# Why the Geneve Source UDP Port Changed in Transit

Private site A sends a Geneve packet to public site B. The source UDP port seen at B differs from the one sent by A. A NAT device between the two sites rewrote it.

## Captures

Egress at site A:

```
12:07:14.463979 IP (tos 0x0, ttl 64, id 57110, offset 0, flags [none], proto UDP (17), length 120)
    9.60.138.217.6081 > 13.121.90.155.6081: [bad udp cksum 0xfc9e -> 0xca7a!] Geneve, Flags [none], vni 0x1
        IP (tos 0x0, ttl 64, id 11958, offset 0, flags [DF], proto ICMP (1), length 84)
    192.168.1.2 > 192.168.1.3: ICMP echo request, id 37005, seq 1, length 64
```

Ingress at site B:

```
17:07:14.516249 IP (tos 0x0, ttl 46, id 57110, offset 0, flags [none], proto UDP (17), length 120)
    129.41.87.1.33296 > 10.251.64.6.6081: [udp sum ok] Geneve, Flags [none], vni 0x1
        IP (tos 0x0, ttl 64, id 11958, offset 0, flags [DF], proto ICMP (1), length 84)
    192.168.1.2 > 192.168.1.3: ICMP echo request, id 37005, seq 1, length 64
```

## What changed in transit

| Field | Site A (egress) | Site B (ingress) |
|---|---|---|
| Source IP | 9.60.138.217 (private/internal) | 129.41.87.1 |
| Source UDP port | 6081 | 33296 |
| Destination IP | 13.121.90.155 | 10.251.64.6 |
| Destination port | 6081 | 6081 |
| IP ID | 57110 | 57110 |

- **The source IP changed too.** A source NAT (SNAT/masquerade) rewrote 9.60.138.217 to 129.41.87.1.
- **The destination IP changed.** 13.121.90.155 became 10.251.64.6. This is a DNAT, or a 1:1 public-to-private mapping in front of B. It looks like a cloud public IP mapped to B's private address.
- **The IP ID is the same (57110) on both sides.** This is the same packet, modified in flight and not regenerated. The TTL dropped from 64 to 46, which is about 18 hops.

## Why the source port was rewritten

A stateful NAT keeps a translation table keyed on the 5-tuple. Two common reasons it picked a new source port:

1. **Port 6081 was already in use or reserved.** A NAT doing PAT (port address translation) shares one public IP among many hosts. It remaps ports so flows from different internal hosts don't collide. Other hosts may already hold 129.41.87.1:6081, or the NAT may avoid well-known or low ports. It picked an ephemeral port, 33296.
2. **The NAT rewrites ports by policy.** Many NATs (Linux `MASQUERADE` with `--random`, and most carrier-grade or cloud NATs) allocate source ports from an ephemeral range. This hides the original port and avoids collisions.

Linux conntrack, for example, tries to preserve the source port. It only changes it when the port is already taken by another flow with the same destination. Many commercial and cloud NAT gateways always remap.

## Side effects to watch for

- **UDP checksum.** Site A shows `bad udp cksum`. That is normal for tcpdump on the sending host with checksum offload, because the NIC fills it in later. Site B shows `udp sum ok`, so the NAT recomputed the checksum correctly after rewriting the addresses and port.
- **Replies must go back to 129.41.87.1:33296.** If B's Geneve endpoint replies to 6081, the reply will not match the NAT mapping and may be dropped. B should reply to the observed source IP and port, or use a symmetric setup.
- **Geneve receivers shouldn't depend on the source port.** Geneve (RFC 8926) uses the UDP source port as an entropy value for ECMP hashing. The destination port, 6081, is what identifies it as Geneve. So B still decodes it correctly. If your code or eBPF program filters on `sport == 6081`, it will miss this traffic. Match on `dport == 6081` instead.
- **Keep the NAT mapping alive.** UDP mappings time out, often in 30–120 seconds. Send periodic keepalives from A so the mapping persists. This is needed if B needs to initiate traffic back to A.

## To confirm

On A, capture on the egress interface and on the NAT or gateway if you control it. Look at the conntrack table (`conntrack -L -p udp --dport 6081`) or the NAT gateway logs to see the translation entry.
