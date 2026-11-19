# IP flags `[DF]`, MTU and fragmentation

Example tcpdump capture on `geneve0`:

```
gabor@gabor-rtp-1:~/geneve-poc/eBPF-proxy-nat$ sudo tcpdump -nn -vvv -l -i geneve0
tcpdump: listening on geneve0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:42:18.596832 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto ICMP (1), length 1452)
    192.168.42.100 > 192.168.42.3: ICMP echo request, id 49681, seq 1, length 1432
```

## What `flags [DF]` means

`flags [DF]` is the **Don't Fragment** bit in the IPv4 header. It's one of three flag bits in the flags field:

| Bit | Name | Meaning |
|---|---|---|
| 0 | Reserved | Must be 0 |
| 1 | **DF** | Don't Fragment |
| 2 | MF | More Fragments |

**What it does:** if a packet with DF set is bigger than the MTU of a link on its path, the router must not fragment it. It drops the packet and sends back an ICMP "Destination unreachable – Fragmentation needed" (type 3, code 4) message. tcpdump prints `flags [DF]` when this bit is set, and `flags [none]` when no flag is set.

## In the capture above

- `length 1452` is the total IP packet size: 20 bytes of IP header, 8 bytes of ICMP header and 1424 bytes of payload. tcpdump reports the ICMP length as 1432, which is the ICMP header plus its data.
- `id 0` and `flags [DF]` together are typical of Linux. Packets that will never be fragmented get a zero IP ID.
- `offset 0` with no MF flag means this is a whole, unfragmented packet.

## Why it matters for the Geneve setup

Geneve encapsulation adds overhead of roughly 50 bytes or more (outer IP, UDP, Geneve header, and the inner Ethernet header if present). A 1452-byte inner packet therefore becomes about 1500 bytes or more on the wire. That is right at the underlay MTU limit, so any extra option or header could push it over.

Because DF is set, the packet can't be fragmented on the underlay. If it doesn't fit, you will see silent drops or ICMP "frag needed" messages.

## Ways to test

- `ping -M do -s <size> 192.168.42.3` sets DF explicitly. Increase `<size>` until it fails to find the real path MTU.
- `ping -M dont -s <size> ...` clears DF, so the packet can be fragmented.
- `ip link show geneve0` shows the interface MTU. It should be the underlay MTU minus the encapsulation overhead.
