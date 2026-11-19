# IPv4 Header Options

In practice you rarely see IPv4 options at all. Nearly all normal TCP, UDP and Geneve traffic has `ihl == 5`. The ones that do show up are:

| Type | Name | Where it appears |
|---|---|---|
| 0 | End of Option List (EOOL) | Terminates the list. Also used as padding. |
| 1 | No-Operation (NOP) | One-byte padding that aligns later options to 32-bit boundaries. |
| 148 (0x94) | Router Alert (RFC 2113) | The most common real-world option. IGMP, MLD-related traffic, RSVP and some multicast and QoS signaling use it. It tells routers to inspect the packet. |
| 7 | Record Route | Diagnostics, for example `ping -R`. Rare, and limited to 9 hops. |
| 68 | Timestamp | Diagnostics, for example `ping -T`. Rare. |
| 131 / 137 | Loose / Strict Source Route | Mostly historical. It is a security risk, so most hosts and firewalls drop it by default (`accept_source_route=0` on Linux). |
| 130 | Security / CIPSO (type 134) | Labeled networking in some government and SELinux environments. |

Each option is either a single byte (EOOL, NOP) or type, length, then data. The type byte is a copied flag (1 bit), an option class (2 bits), and an option number (5 bits).

Many routers handle packets with options in a slow path, and many ISPs and firewalls drop them. That is why options are close to nonexistent on the public internet. Internal traffic that carries them is mostly IGMP with Router Alert.

## Handling in the Geneve relay / NAT program

There are two safe approaches:

- **Drop or pass through anything with `ip->ihl != 5`.** This is simplest and fine for a PoC. Check it before you touch the UDP header.
- **Support options by computing the UDP offset as `ip->ihl * 4`.** The verifier needs a bounds check against `data_end` after the computation.

Don't confuse these with Geneve options. Those are separate TLVs after the 8-byte Geneve header, and their length is in the `opt_len` field (in 4-byte units). They have nothing to do with the IP options above.
