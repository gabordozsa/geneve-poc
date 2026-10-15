# eBPF Proxy — Geneve Relay Filter Summary

## Overview

`geneve_relay.c` implements two TC (Traffic Control) eBPF programs attached to the `geneve` interface. Together they relay or terminate Geneve-encapsulated packets between proxies, using custom Geneve TLV options to carry proxy identity (ID hashes) across hops.

---

## Ingress filter — `geneve_ingress_redirect()`

Attached to **TC ingress** of `geneve-in`. By the time it runs, the Geneve driver has already decapsulated the outer UDP/IP envelope and made tunnel metadata available via the `skb`.

1. **Reads the custom Geneve TLV option** (`opt_class=0x0101`, `type=0x2A`) to extract the **destination** and **source proxy ID hashes** embedded in the packet.
2. **If `dst_id_hash == LOCAL_ID_HASH`** → the packet has reached its final destination (`local_ingress_packet()`):
   - Looks up the locally assigned overlay IP for the source proxy (`hash2ip` map).
   - **Rewrites both inner src and dst IP addresses** to local overlay IPs, and recomputes L3/L4 checksums (TCP and UDP).
   - Returns `TC_ACT_OK` to deliver the packet locally.
3. **Otherwise** → this is a relay hop (`relay_ingress_packet()`):
   - Converts both `dst_id_hash` and `src_id_hash` to compact 8-bit local indices (`hash2ind` map).
   - **Encodes those two indices into the upper 16 bits of `skb->mark`** to pass them to the egress filter.
   - Calls `bpf_redirect()` back out on the same interface to re-encapsulate and forward.

---

## Egress filter — `geneve_egress_rewrite()`

Attached to **TC egress** of `geneve-in` at higher priority than the kernel's "tunnel_key unset" filter, so it runs first.

1. **Reads `dst_hash_index` and `src_hash_index`** from the upper 16 bits of `skb->mark`.
2. **If both are zero** → locally originated packet (`local_egress_packet()`):
   - Looks up the **destination proxy ID hash** from the inner dest IP (`ip2hash` map).
   - Looks up the **next-hop underlay IP** for that hash (`hash2nh` map).
   - Uses `LOCAL_ID_HASH` as the source ID hash.
   - Calls `set_tunnel_key_and_opt()` to set the Geneve tunnel key (remote IP, VNI=42, TTL=64) and inject the custom TLV option carrying `dest_id_hash` / `src_id_hash`.
3. **If non-zero** → relayed packet (`relay_egress_packet()`):
   - Recovers both ID hashes from the indices in `skb->mark` (`ind2hash` map).
   - Looks up the next-hop underlay IP for the destination hash.
   - Calls `set_tunnel_key_and_opt()` with the original (preserved) src/dst hashes, re-encapsulating for the next relay hop.

---

## Summary

The **ingress filter** decapsulates arriving Geneve packets and decides between *local delivery* (rewriting inner IPs to local overlay addresses) and *relay* (encoding forwarding context into `skb->mark` and redirecting).

The **egress filter** re-encapsulates outgoing packets into Geneve tunnels with the correct next-hop underlay IP and proxy ID metadata in the TLV option, handling both locally originated and relayed packets.

---

## BPF Maps

| Map | Key | Value | Purpose |
|-----|-----|-------|---------|
| `ip2hash` | inner dest IP | dest proxy ID hash | Egress: resolve dest ID hash from inner dest IP (local packets) |
| `hash2ip` | proxy ID hash | overlay IP | Ingress: resolve local overlay IP from src ID hash (local delivery) |
| `hash2nh` | proxy ID hash | next-hop underlay IP | Egress: resolve next-hop underlay IP for re-encapsulation |
| `hash2ind` | proxy ID hash | 8-bit local index | Ingress: compact hash → index for `skb->mark` encoding |
| `ind2hash` | 8-bit local index | proxy ID hash | Egress: recover hash from index stored in `skb->mark` |
