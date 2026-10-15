# Test Configuration — 4-VM Geneve Relay Topology

The script [`tunnel-relay-4-vm.sh`](tunnel-relay-4-vm.sh) sets up a **4-node overlay network** where each node is a virtual machine acting as a Geneve proxy/relay. The configuration is driven by a `SITE` argument (`VS1`–`VS4`) so the same script bootstraps every node.

## Network Topology

| Site | Underlay IP   | Overlay IP           | ID Hash |
|------|---------------|----------------------|---------|
| VS1  | `10.251.64.6` | `192.168.42.100/24`  | 100     |
| VS2  | `10.251.0.5`  | `192.168.42.100/24`  | 200     |
| VS3  | `10.251.64.4` | `192.168.42.100/24`  | 300     |
| VS4  | `10.251.0.4`  | `192.168.42.100/24`  | 400     |

All four sites deliberately share the **same overlay IP** (`192.168.42.100`) — a key design point that mimics a router network where overlay IP-to-ID-hash mappings are managed independently at each site.

## What Each Node Gets

1. **A `geneve0` interface** — created in `external` (metadata) mode on UDP port 6081, with an MTU of 1438 bytes (accounting for 62 bytes of Geneve + custom TLV overhead on a 1500-byte physical link).
2. **Static ARP/neighbour entries** — one per remote peer, pre-populated to avoid ARP traffic over the tunnel. Each site uses a locally scoped IP offset (e.g. VS2 uses `192.168.42.2x`) so that the eBPF maps can distinguish peers even though all sites share the same overlay address.
3. **eBPF TC filters** — the `user_control` binary is launched to attach and populate the eBPF maps (`ip2hash`, `hash2ip`, `hash2nh`, `hash2ind`, `ind2hash`) on `geneve0`, telling the [`geneve_relay.c`](geneve_relay.c) programs how to route and rewrite packets.

## Traffic Flow

The intended test path is a **multi-hop chain: VS1 → VS2 → VS3 → VS4**. A client-side proxy runs on **VS1** and connects through the Geneve overlay to a server-side proxy on **VS4**. VS2 and VS3 act as pure relay nodes — the eBPF ingress filter reads the custom Geneve TLV option (class `0x0101`, type `0x2A`) carrying `[dest ID hash, src ID hash]`, and either:

- **Delivers** the packet locally (if the dest hash matches the node's own `LOCAL_ID_HASH`), rewriting inner src/dst addresses and fixing L3/L4 checksums, or
- **Relays** it by re-encapsulating with the next-hop underlay IP and forwarding back out `geneve0`.

## Application Layer

- **VS4** runs a server-side proxy (`proxy -l 5201 -r 127.0.0.1 -p 5301 -L -D -n server`) fronting a simple `python3 -m http.server` backend on port 5301.
- **VS1** runs a client-side proxy (`proxy -l 5201 -r 192.168.42.4 -p 5201 -R -n client`) that forwards connections through the overlay chain.
- TLS between proxies is enabled by default (`USE_TLS=1`), requiring a pre-generated `server.crt`/`server.key` in the `certs/` directory.
- A `curl http://127.0.0.1:5201/` on VS1 exercises the full end-to-end path.

