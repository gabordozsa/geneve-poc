# Outer UDP checksum and the `udp_port_rewrite()` egress filter

## Problem

Topology: `tunnel-relay-4-vm.sh`, VS1 -> VS2 -> VS3 -> VS4 over Geneve.

With the `udp_port_rewrite` TC egress filter on `ens3` (see
[`eBPF-proxy-nat/geneve_relay_nat.c`](../eBPF-proxy-nat/geneve_relay_nat.c)):

- `ping 192.168.42.4` from VS1 works.
- The proxy TCP connection (`proxy -r 192.168.42.4 -p 5201`) hangs. The TCP SYN is
  retransmitted but never reaches VS4.
- If the filter does not change the outer UDP ports, the proxy works.

On VS2, the SYN packets show `bad udp cksum 0xXXXX -> 0x5f9e`. The "expected" value is the
same on every retransmit, while the value in the packet changes. The Geneve driver on
VS2 drops the packets, so they are never relayed. The ping packets are accepted
(`udp sum ok`).

The inner TCP checksum is correct (`cksum ... (correct)` in the capture). The failing
checksum is the **outer UDP checksum** of the Geneve packet.

## What the outer UDP checksum covers

RFC 768: the IPv4 pseudo-header (outer src/dst IP, protocol 17, UDP length), the UDP
header (including both ports) and the payload. For Geneve the payload is the Geneve
header, its options and the whole inner IP packet. So changing an outer UDP port
invalidates the outer checksum, and it must be updated (or disabled) afterwards.

## Root cause

The outer UDP checksum is in a different state for different inner packets, and
the filter sees both as `ip_summed == CHECKSUM_PARTIAL`. The Geneve driver
(`udp_set_csum()`) builds the outer header differently depending on the inner packet:

| | Ping (inner ICMP) | TCP SYN (local socket) |
|---|---|---|
| Inner checksum | Already computed | `CHECKSUM_PARTIAL`, to be finished later |
| What the driver does | Marks the outer UDP header `CHECKSUM_PARTIAL` and stores only the pseudo-header sum | Local checksum offload (LCO): computes the final outer checksum and leaves `csum_start` on the inner TCP header |
| `ip_summed` at the `tc` egress filter | 3 (`CHECKSUM_PARTIAL`) | 3 (`CHECKSUM_PARTIAL`) |
| `csum_start - transport_header` | 0 | 48 (outer UDP 8 + Geneve 8 + option 12 + inner IP 20) |
| `csum_start` points at | outer UDP header | inner TCP header |
| Outer `udp->check` holds | pseudo-header seed | final checksum |
| Correct action when ports change | nothing, the checksum is finished later and covers the new ports | update the checksum by hand (RFC 1624) |

`bpf_l4_csum_replace()` does nothing for a `CHECKSUM_PARTIAL` skb when
`BPF_F_PSEUDO_HDR` is not set, because it assumes the checksum will be completed later. That is right for the ping and wrong for the TCP SYN: the finisher for the SYN is the
inner TCP checksum, which does not cover the outer ports. So the outer checksum goes
stale after the port rewrite and VS2 drops the packet.

## Evidence

All values come from the captures and traces of this investigation.

1. **Debug printk in `udp_port_rewrite()`**, before and after `bpf_l4_csum_replace()`:

   | Packet | Outer `udp->check` before | After the helper | Ports |
   |---|---|---|---|
   | TCP SYN | `0xdec2` | `0xdec2` | 39068 -> 6081 |
   | Ping | `0x5682` | `0x5682` | 34142 -> 6081 |

   The helper reported success but changed nothing in both cases.

2. **RFC 1624 update by hand** (`new = ~(~old + ~old_port + new_port)`):
   - SYN: `~0xdec2 + ~0x989c + 0x17c1` -> `0x5f9e`. This equals the "expected" value in the
     VS2 capture, so for the SYN the field holds a final checksum and needed this update.
   - Ping: the same update gives `0xc41f`. That would be wrong: `0x5682` is exactly the
     outer pseudo-header sum
     (`0x0afb + 0x4006 + 0x0afb + 0x0005 + 0x0011 + 0x0070`), i.e. a seed. The NIC or
     stack sums the real UDP header on top of it, including the new ports, so a manual
     port delta would be counted twice.

3. **bpftrace on `__dev_queue_xmit`**, the point the `tc` egress filter runs at, outer
   UDP packets to 10.251.0.5:

   | Packet | `ip_summed` | `csum_start` | `transport_header` | diff |
   |---|---|---|---|---|
   | Ping | 3 | 68 | 68 | 0 |
   | Proxy SYN | 3 | 280 | 232 | 48 |

4. **bpftrace on `dev_hard_start_xmit`**, later in the path, showed `ip_summed=0` for the SYN. By that point `validate_xmit_skb()`
   had computed the inner TCP checksum in software and reset the state. A probe at
   that point does not show what the filter sees.

## Why the filter cannot just fix it

- `__sk_buff` does not expose `ip_summed` or `csum_start`, so a plain `tc` program
  cannot tell a seed from a final checksum.
- Both cases are `PARTIAL`, so `ip_summed` alone would not separate them anyway. The
  discriminator is `csum_start == transport_header` (seed) versus `csum_start != transport_header` (final).

## Solutions

### 1. Zero outer UDP checksum (`BPF_F_ZERO_CSUM_TX`)

- In `set_tunnel_key_and_opt()` pass `BPF_F_ZERO_CSUM_TX` to `bpf_skb_set_tunnel_key()`, so
  the Geneve driver sends the outer UDP checksum as 0.
- In `udp_port_rewrite()` remove the `bpf_l4_csum_replace()` calls. The ports can be rewritten
  with no checksum work.

Pros: small change, no kernel dependency, handles both cases.
Cons: a zero UDP checksum is valid for IPv4 (RFC 768), but a NAT or firewall on the path may
drop such packets. The receiving Geneve driver must also accept it.
Not yet tried on the VMs.

### 2. Check `csum_start` in the filter and fix the checksum by hand

- Get the kernel skb with `bpf_cast_to_kern_ctx()` (needs a `vmlinux.h`, BTF and a kernel that supports the kfunc).
- If `csum_start == transport_header`: the field is a seed, change only the ports.
- Otherwise: the field is final, so apply the RFC 1624 update for each port change
  and write it with `bpf_skb_store_bytes()` (do not rely on `bpf_l4_csum_replace()`).

Pros: keeps a real outer checksum.
Cons: more code, `vmlinux.h`/CO-RE build setup, kernel-version dependency, to be tested on each VM.
Not implemented.

### 3. Compare `udp->check` with the pseudo-header sum

- Compute the outer pseudo-header sum in BPF (src IP, dst IP, protocol, UDP length, folded to 16 bits).
- If it equals `udp->check`, treat it as a seed and change only the ports. Otherwise apply the RFC 1624 update.

Pros: no `vmlinux.h`.
Cons: a final checksum equals the pseudo-header sum with probability about 1 in 65536, so that packet would be dropped
(TCP retransmits would hide it). GSO packets need a test. Not implemented.

### 4. Not recommended

- `ethtool -K ens3 tx off`: the outer checksum is already final for the SYN, so turning off offload does not
  recompute it.
- Writing `udp->check = 0` in the egress filter: breaks the ping case, because the
  stack then finishes a checksum from a zero seed.

## Recommendation

Use option 1 for the proof of concept. Use option 2 if the underlay is known to drop zero-checksum UDP.

## Current state of the code

- [`udp_port_rewrite()`](../eBPF-proxy-nat/geneve_relay_nat.c) still has the original `bpf_l4_csum_replace()` calls.
- It also has temporary `DEBUG` printks of the outer UDP checksum, and an `asm volatile("" : "+r"(udp_off))` that keeps the verifier from rejecting the 4-argument printk.
  Remove both once a fix is chosen.

## Reproduce

Trace the filter:

```
sudo cat /sys/kernel/tracing/trace_pipe | grep DEBUG
```

Show the checksum state at the filter, for outer UDP packets to 10.251.0.5 (adjust the address for other hops):

```
sudo bpftrace -e '
kprobe:__dev_queue_xmit
{
  $skb = (struct sk_buff *)arg0;
  $ip  = $skb->head + $skb->network_header;
  if (*(uint8 *)($ip + 9) == 17 && *(uint32 *)($ip + 16) == 0x0500fb0a) {
    printf("ip_summed=%d csum_start=%d transport_hdr=%d diff=%d len=%d\n",
           $skb->ip_summed, $skb->csum_start, $skb->transport_header,
           $skb->csum_start - $skb->transport_header, $skb->len);
  }
}'
```

Capture on the sender and receiver:

```
sudo tcpdump -nn -vvv -l -i ens3 udp port 6081
```

## Appendix: GSO packets

GSO is Generic Segmentation Offload. It lets the kernel send one large "super-packet" through
the network stack and split it into MTU-sized packets as late as possible.

**Why it exists**
- Per-packet work in the stack (routing, netfilter, qdisc, tc/BPF filters) is costly.
- With GSO, a TCP socket can hand the stack up to 64 KB in a single skb instead of about
  45 packets of 1448 bytes.
- The split into real packets happens right before the driver, in software
  (`skb_gso_segment()`), or in hardware if the NIC supports it. Hardware segmentation is
  called TSO for TCP and USO for UDP.

**What it looks like to the stack**
- One `sk_buff` has `skb_is_gso(skb)` true and carries `gso_size` (the segment payload size,
  roughly the MSS) and `gso_type` (for example TCPv4).
- The headers are those of the first segment. Lengths, sequence numbers and checksums are
  fixed up per segment during segmentation.
- The TCP checksum is `CHECKSUM_PARTIAL`, because each segment needs its own checksum.

**Why it matters for this problem** (not tested)
- The SYN is a single small packet, so GSO does not apply to it.
- During a real transfer, a large inner TCP skb can be wrapped by the Geneve driver. As far
  as I recall, the driver then uses tunnel GSO flags such as `SKB_GSO_UDP_TUNNEL` and
  `SKB_GSO_UDP_TUNNEL_CSUM`. The outer UDP header is built once, and the outer length and
  checksum are fixed per segment when the skb is segmented.
- An egress filter that edits `udp->check` on such an skb sees a value that is not the final
  per-segment checksum. A hand-computed update (solutions 2 and 3) could then be wrong.
- `BPF_F_ZERO_CSUM_TX` (solution 1) avoids this, because the outer checksum is 0 for every
  segment.
- Ports are the same for all segments, so rewriting them on the super-packet is fine. Only
  the checksum is the concern.

**How to check:** run a large transfer through the proxy and watch `skb->len` in the
`__dev_queue_xmit` bpftrace probe from the Reproduce section. A `$skb->len` far above the MTU
means a GSO skb.

## Tracing data for Geneve encapsulation

**Inner TCP, no GSO**

Locally created packet:

```
<idle>-0       [002] b.sb. 3903672.588182: bpf_trace_printk: [00000064] udp egress: DEBUG outer pseudo-header sum: 5662, udp csum: 76c0
<idle>-0       [002] b.sb. 3903672.588182: bpf_trace_printk: [00000064] udp egress: DEBUG gso_size: 0 gso_segs: 1 len: 114
```

Outer udp->csum is final value

Forwarded packet:

```
<idle>-0       [003] b.s6. 3832246.486510: bpf_trace_printk: [000000c8] udp egress: DEBUG outer pseudo-header sum: 5668, udp csum: 5668
<idle>-0       [003] b.s6. 3832246.486511: bpf_trace_printk: [000000c8] udp egress: DEBUG gso_size: 0 gso_segs: 0 len: 122
```

Outer udp->csum is final value for local packet BUT pseudo header for forwarded packet.

**Inner TCP, GSO**

Locally created packet:

```
proxy-2509169 [001] b..7. 3904011.478607: bpf_trace_printk: [00000064] udp egress: DEBUG outer pseudo-header sum: 51f3, udp csum: 51f3
proxy-2509169 [001] b..7. 3904011.478607: bpf_trace_printk: [00000064] udp egress: DEBUG gso_size: 1400 gso_segs: 46 len: 64514
```

Forwaded packet:

```
<idle>-0       [003] b.s6. 3832584.343691: bpf_trace_printk: [000000c8] udp egress: DEBUG outer pseudo-header sum: c3c0, udp csum: c3c0
<idle>-0       [003] b.s6. 3832584.343692: bpf_trace_printk: [000000c8] udp egress: DEBUG gso_size: 1400 gso_segs: 20 len: 28114
```

Outer udp->csum is pseudo header for both local and forwarded.

**Inner UDP, no GSO**

Local packet:

```
nc-2516949 [000] b..6. 3906050.873210: bpf_trace_printk: [00000064] udp egress: DEBUG outer pseudo-header sum: 564f, udp csum: 3f1d
nc-2516949 [000] b..6. 3906050.873210: bpf_trace_printk: [00000064] udp egress: DEBUG gso_size: 0 gso_segs: 0 len: 95
```

Forwarded packet:

```
<idle>-0       [002] b.s6. 3832934.988026: bpf_trace_printk: [000000c8] udp egress: DEBUG outer pseudo-header sum: 5662, udp csum: 5662
          <idle>-0       [002] b.s6. 3832934.988027: bpf_trace_printk: [000000c8] udp egress: DEBUG gso_size: 0 gso_segs: 0 len: 114
```

Outer udp->csum is final for local BUT pseudo for forwarded.

**Inner UDP, GSO**

Only for local (forwarding node deals with single datagrams ....?)

```
python3-2523406 [003] b..6. 3908375.511987: bpf_trace_printk: [00000064] udp egress: DEBUG outer pseudo-header sum: 40ab, udp csum: 40ab
python3-2523406 [003] b..6. 3908375.511988: bpf_trace_printk: [00000064] udp egress: DEBUG gso_size: 1400 gso_segs: 43 len: 60090
```

Outer udp->csum is the pseudo header.

## Inner ICMP**

Local packet:

```
ping-2525133 [001] b..6. 3908617.182230: bpf_trace_printk: [00000064] udp egress: DEBUG outer pseudo-header sum: 5682, udp csum: 5682
ping-2525133 [001] b..6. 3908617.182231: bpf_trace_printk: [00000064] udp egress: DEBUG gso_size: 0 gso_segs: 0 len: 146
```

Forwarded packet:

```
<idle>-0       [003] b.s6. 3833782.941894: bpf_trace_printk: [000000c8] udp egress: DEBUG outer pseudo-header sum: 5680, udp csum: 5680
<idle>-0       [003] b.s6. 3833782.941895: bpf_trace_printk: [000000c8] udp egress: DEBUG gso_size: 0 gso_segs: 0 len: 146
```

## Update: why `BPF_F_PSEUDO_HDR` gives a wrong checksum for the local TCP SYN

The code now sets `BPF_F_PSEUDO_HDR` for non-ICMP, non-GSO packets (see `csum_flags` in
[`udp_port_rewrite()`](../eBPF-proxy-nat/geneve_relay_nat.c)). That makes the helper change the field, but
with the wrong formula.

Trace of a local TCP SYN (VS1) and the capture on VS2:

| | Value |
|---|---|
| Outer `udp->check` before | `0x3f75` |
| Source port change | 54249 (`0xd3e9`) -> 6081 (`0x17c1`) |
| Written by `bpf_l4_csum_replace()` | `0x834c` |
| Expected by VS2 (tcpdump) | `0xfb9d` |

The helper's behavior depends on `skb->ip_summed` (from memory of `net/core/utils.c`
and the `0x834c` result; not checked against the kernel source):

| `ip_summed` | `BPF_F_PSEUDO_HDR` | What the helper does |
|---|---|---|
| not `PARTIAL` | any | RFC 1624 on a final checksum: `~(~old + ~from + to)` |
| `PARTIAL` | not set | nothing |
| `PARTIAL` | set | seed update: `old - from + to` (no inversion) |

The SYN is `PARTIAL` but holds a final checksum. With the flag the seed formula is applied to it:

```
0x3f75 + ~0xd3e9 (0x2c16) + 0x17c1 = 0x834c      <- what was sent (wrong)
~(~0x3f75 (0xc08a) + 0x2c16 + 0x17c1) = 0xfb9d    <- RFC 1624, what VS2 expects
```

Ping works because it is a seed: the checksum is finished later over the new ports.

The decision cannot be based on `inner_proto` or `gso_size`. A forwarded TCP or UDP packet has a seed
(`udp->check` equals the pseudo-header sum), so the `PSEUDO_HDR` path with the normal formula is
right for it and wrong for the local SYN.

## Doing the RFC 1624 update with the helpers

RFC 1624 reduces to `new = old + from - to` in ones'-complement arithmetic (`~(~a + b) = a - b`).
The seed formula is `old - from' + to'`, so swapping the arguments gives the RFC 1624 result.

### A. Swap `from` and `to` in `bpf_l4_csum_replace()`

```c
bpf_l4_csum_replace(skb, csum_off, new_port, old_port,   // swapped
                    BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | sizeof(new_port));
```

Check: `0x3f75 + ~0x17c1 (0xe83e) + 0xd3e9 = 0xfb9d`.

### B. `bpf_csum_diff()` plus `bpf_l4_csum_replace()`

With `from = 0` and size 0 in the flags, the helper takes `to` as a precomputed diff. Swap the buffers so
the diff is `~to + from`:

```c
struct { __be16 p; __be16 pad; } from = { old_port, 0 }, to = { new_port, 0 };
__s64 diff = bpf_csum_diff((__be32 *)&to, sizeof(to), (__be32 *)&from, sizeof(from), 0);
if (diff < 0)
    return TC_ACT_SHOT;
bpf_l4_csum_replace(skb, csum_off, 0, diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
```

- `bpf_csum_diff()` needs sizes that are a multiple of 4, so each 16-bit port goes in a 4-byte buffer.
- Both ports can be done in one call with `{old_src, old_dst}` and `{new_src, new_dst}`.
- This gives the same result as A. Its only advantage is one call for both ports.

### C. Compute and store the checksum yourself

Compute the RFC 1624 value and write it with `bpf_skb_store_bytes(skb, csum_off, &csum, 2, 0)`.
This does not depend on `ip_summed`. If the result is 0, store `0xffff`.

### Caveats for A and B

- **Seed vs. final:** the swapped update is only right when `udp->check` is a final checksum. For a seed
  (forwarded packets, ICMP, GSO) leave the checksum alone and change only the ports. The test is
  `udp->check == outer pseudo-header sum`.
- **Order:** compute the pseudo-header sum before the first port rewrite. The current debug code computes it
  after the source port has changed.
- **False match:** a final checksum equals the pseudo-header sum about 1 time in 65536. That packet would be
  mishandled (TCP retransmits hide it).
- **Depends on `PARTIAL`:** if the skb reaches the filter as `NONE` or `COMPLETE`, the helper does the normal
  RFC 1624 update, and the swapped call is wrong. C does not have this problem.
- **GSO:** not tested. The outer checksum on a GSO super-packet is a seed, so use the seed path.

None of this is implemented or tested on the VMs yet.

## Q&A: packets longer than the MTU and "bad udp cksum" in a tcpdump on VS2

Capture seen on VS2 while the proxy on VS1 talked TLS to the proxy on VS4:

```
10.251.64.4.6081 > 10.251.0.5.6081: [bad udp cksum 0x603b -> 0x5d97!] Geneve, ... vni 0x2a, ... length 2623
    IP ... length 2575) 192.168.42.100.5201 > 192.168.42.41.46664: Flags [P.], cksum 0xdfdf (incorrect -> 0x4b85), ... length 2523
```

Both symptoms are most likely capture artifacts from receive offload (GRO) on VS2, not packets that were sent over the wire. This has not been confirmed on the VMs. A test is given at the end.

### Why the length exceeds the MTU

- The sizes add up exactly: 2623 = 2575 (inner IP) + 20 (outer IP) + 8 (UDP) + 8 (Geneve) + 12 (OVS option). The 2523 bytes of TCP payload is more than one segment, since the overlay MTU is 1452 and the MSS is about 1400. So the capture shows at least two inner TCP segments combined into one packet.
- The outer ens3 MTU is 1500, so a 2623-byte frame cannot have been on the wire. The packet was probably rebuilt after arrival. `tcpdump` hooks in before the GRO result is split back up, and GRO lets the kernel merge consecutive same-flow segments into one large skb. Geneve has a GRO handler (`geneve_gro_receive`), so it can merge UDP-encapsulated TCP flows too.
- The sender (VS3, 10.251.64.4) has the same behaviour on egress. A TC or tcpdump hook sees a GSO skb larger than the MTU (see [GSO-FRAGMENTATION.md](GSO-FRAGMENTATION.md)). The NIC or the GSO layer splits it into MTU-sized packets afterwards.

### Why the checksums are bad

- When GRO merges packets, it keeps the headers of the first segment and only updates the length fields. The outer UDP checksum (`0x603b`) and the inner TCP checksum (`0xdfdf`) therefore no longer match the merged length. That is why `tcpdump` reports "bad udp cksum" and "incorrect".
- The kernel already validated the individual segments on receive. It tracks that with `CHECKSUM_UNNECESSARY` or `CHECKSUM_PARTIAL`, and `tcpdump` ignores that state and recomputes from the bytes.
- It is not a problem as long as the TLS handshake works and the transfer completes. Packets with a truly bad checksum would be dropped, and the connection would stall or retransmit.

### What would be a real problem

- The same large packet showing up on the wire as a frame over 1500 bytes. Check this by capturing on the other side, for example on VS1, or on VS3's `ens3` after segmentation.
- Counters rising in `nstat -az | grep -i -E 'csum|InCsumErrors'` or `ethtool -S ens3`.
- The eBPF code interacting with merged skbs. In `geneve_relay_nat.c` the outer UDP checksum logic only uses the LCO path when `!skb->gso_size`. For merged or GSO skbs it takes the incremental `bpf_l4_csum_replace` path instead, so the CHECKSUM_PARTIAL seed is treated differently. That is the code to watch if throughput collapses or you see `InCsumErrors` at the next hop.

### How to confirm

```bash
# On VS2: if the 2000+ byte packets disappear, it's GRO
ethtool -k ens3 | grep -E 'generic-receive-offload|rx-udp-gro|tx-udp_tnl'
ethtool -K ens3 gro off rx-udp-gro-forwarding off
tcpdump -ni ens3 -vv udp port 6081

# On the next hop (VS1 or VS4), check that no frame exceeds 1500 bytes
tcpdump -ni ens3 -e udp port 6081 and greater 1500
```

With GRO off, the frames should be at most 1500 bytes and the checksums should show as valid. If oversized frames still show up on the next hop's capture, look at how the relay handles `gso_size` on egress.

## Finding: swapped-argument update on a relay corrupts the seed, but traffic still passes

Setup: VS1 sends TCP to VS4 through VS2 and VS3 (`tunnel-relay-4-vm.sh`). In
[`udp_port_rewrite()`](../eBPF-proxy-nat/geneve_relay_nat.c) the swapped `bpf_l4_csum_replace()`
arguments (`lco_csum = 1`) are chosen when `src_id_hash == LOCAL_ID_HASH`. Two runs were made:

- **Run 1:** the condition was active. It is true only on the originator (VS1). On a relay such as
  VS2, `src_id_hash` is VS1's hash, so `lco_csum` was 0 and the helper changed nothing.
- **Run 2:** the condition was commented out, so `lco_csum` was 1 for every non-ICMP, non-GSO
  packet, including the ones VS2 relays.

Both runs completed the TCP connection end to end. `udp sum ok` was reported on VS1 for the packets
VS2 relayed, and no checksum drop counters rose on VS1 or VS3.

### What the traces show

On VS2 the outer `udp->check` equals the outer pseudo-header sum on every relayed packet, so it is a
`CHECKSUM_PARTIAL` seed, not a final checksum:

| Packet | Check before | Check after (run 1) | Check after (run 2) | Source port |
|---|---|---|---|---|
| Forward SYN | `0x5668` | `0x5668` | `0x8380` | 17625 -> 6081 |
| Reverse SYN-ACK | `0x566a` | `0x566a` | `0x4371` | 1224 -> 6081 |

Run 2 applies the seed formula `old - from + to` with `from` and `to` swapped, which adds
`old_port - new_port` to the seed:

```
0x5668 + ~0x17c1 (0xe83e) + 0x44d9 (17625) = 0x8380    forward
0x566a + ~0x17c1 (0xe83e) + 0x04c8 (1224)  = 0x4371    reverse
```

Both match the traces. The relayed packets have `udp->check == pseudo-header sum`, so leaving
the field untouched (run 1) is the correct action. Run 2 shifted the seed by the wrong amount.

### The VS2 egress capture of run 2

`tcpdump` on VS2's `ens3` flagged every relayed packet it sent: `bad udp cksum 0x8380 -> 0xfb9f`
(forward SYN), `0x4371 -> 0xfbc2` (reverse SYN-ACK). The first value is the field our program
left, and it matches the trace. The second is the final checksum that `tcpdump` computed.
Packets arriving at VS2 from VS1 and VS3 show `udp sum ok`.

A "bad" mark on an outbound offloaded packet does not by itself prove the packet was bad on the wire.
The wire result is shown by the receiver. VS1's capture of the reverse packets VS2 relayed reports
`udp sum ok` in run 2, even though the field left VS2 with the shifted seed (`0x4371` instead of
`0x566a`).

### Why run 2 still works

The seed was wrong, yet the receiver saw a correct final checksum. So whatever completed the
checksum after `tc egress` did not add the field value to the sum of the UDP header and payload.
The likely cause is that the virtual NIC or the hypervisor recomputes the UDP checksum from scratch
for a `CHECKSUM_PARTIAL` packet, rebuilding the pseudo-header from the IP header and ignoring the
field. This is an inference. It has not been proven on these VMs.

Consequences:

- Run 1 (leave the seed alone) is correct under any completion method.
- Run 2 is only correct because this platform ignores the seed. A guest kernel that completes the
  checksum itself (`skb_checksum_help()`, for example with `ethtool -K ens3 tx off`) or a NIC that adds the
  field to its sum would produce a bad outer checksum, and the next hop would drop the packet.
- The earlier note that local packets carry a final checksum and forwarded packets carry a seed
  (see "Tracing data for Geneve encapsulation") still holds. The swapped form is only right for
  the final-checksum case.

### Not yet checked

- The same test on a VS1 trace. On VS1 the swapped path is used in both runs, so this would
  show whether local packets are also hidden by the platform.
- Run 2 with `ethtool -K ens3 tx off` on VS2. The expectation is that VS1 and VS3 would then
  report `bad udp cksum` for the relayed packets and drop them.
- `ethtool -k ens3` offload settings on all four VMs.

### Decision rule to implement

Do not choose the swapped form from `src_id_hash` or `inner_proto`. Compute the outer pseudo-header
sum before the first port rewrite and compare it with `udp->check`:

- Equal: the field is a seed. Rewrite the ports and skip the checksum update.
- Different: the field is a final checksum. Use the swapped form with `BPF_F_PSEUDO_HDR`, or compute
  the RFC 1624 value and store it.

The residual risk is the same as in solution 3: a final checksum equals the pseudo-header sum about 1 time in
65536. Not implemented yet.
