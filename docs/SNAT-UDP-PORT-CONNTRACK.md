# Root Cause Analysis: UDP Port Unreachable Caused by nftables SNAT and Conntrack

## Problem Overview

When sending a ping across a Geneve tunnel from Site A to Site B, Site A emitted an ICMP Port Unreachable (`ICMP udp port 6081 unreachable`, Type 3, Code 3) immediately upon receiving the encapsulated ping reply from Site B.

### Observed Packet Capture (Site A)

```text
11:45:23.424241 IP (tos 0x0, ttl 64, id 17320, offset 0, flags [none], proto UDP (17), length 120)
    9.60.138.217.6081 > 13.121.90.155.6081: [bad udp cksum 0xfc9e -> 0xca7a!] Geneve, Flags [none], vni 0x1
        IP (tos 0x0, ttl 64, id 59699, offset 0, flags [DF], proto ICMP (1), length 84)
    192.168.1.2 > 192.168.1.3: ICMP echo request, id 37025, seq 1, length 64

11:45:23.530475 IP (tos 0x48, ttl 46, id 25000, offset 0, flags [none], proto UDP (17), length 120)
    13.121.90.155.6081 > 9.60.138.217.6081: [udp sum ok] Geneve, Flags [none], vni 0x1
        IP (tos 0x0, ttl 64, id 40758, offset 0, flags [none], proto ICMP (1), length 84)
    192.168.1.3 > 192.168.1.2: ICMP echo reply, id 37025, seq 1, length 64

11:45:23.530510 IP (tos 0xc8, ttl 64, id 47868, offset 0, flags [none], proto ICMP (1), length 148)
    9.60.138.217 > 13.121.90.155: ICMP 9.60.138.217 udp port 6081 unreachable, length 128
        IP (tos 0x48, ttl 46, id 25000, offset 0, flags [none], proto UDP (17), length 120)
    13.121.90.155.6081 > 9.60.138.217.6081: [udp sum ok] Geneve, Flags [none], vni 0x1
        IP (tos 0x0, ttl 64, id 40758, offset 0, flags [none], proto ICMP (1), length 84)
    192.168.1.3 > 192.168.1.2: ICMP echo reply, id 37025, seq 1, length 64
```

---

## Root Cause

The root cause of the "UDP port unreachable" response is the **`nftables` SNAT rule in `POSTROUTING`**:

```nft
table ip nat {
        chain POSTROUTING {
                type nat hook postrouting priority srcnat; policy accept;
                udp dport 6081 counter packets 18 bytes 2160 snat to :6081
        }
}
```

---

## Step-by-Step Breakdown of What Happens

1. **Geneve Driver Generates an Ephemeral Source Port:**
   When the Linux Geneve kernel driver encapsulates the ping request, it sets the destination port to `6081`. By design ([RFC 8926 Section 3.3](https://datatracker.ietf.org/doc/html/rfc8926#section-3.3)), it generates a **random ephemeral source port** (e.g. `49152`) to provide entropy for Equal-Cost Multi-Path (ECMP) load balancing across intermediate hops.

2. **Netfilter SNAT Rewrites the Source Port at Egress:**
   The `snat to :6081` rule intercepts the outbound packet in the `POSTROUTING` chain and rewrites the source port from the ephemeral port to `6081`.

   Netfilter connection tracking (**conntrack**) registers this stateful translation:
   - **Original direction:** `9.60.138.217:<ephemeral_port> -> 13.121.90.155:6081`
   - **Translated on wire:** `9.60.138.217:6081 -> 13.121.90.155:6081`
   - **Expected reply tuple:** `13.121.90.155:6081 -> 9.60.138.217:6081` $\to$ **un-SNAT destination port to `9.60.138.217:<ephemeral_port>`**

3. **Site B Sends the Geneve Reply:**
   Site B sees the request originating from port `6081` and sends the Geneve reply back to `9.60.138.217:6081`.

4. **Conntrack Un-SNATs the Incoming Reply in `PREROUTING`:**
   When the reply arrives on `eth1`, Netfilter conntrack matches the existing flow in `PREROUTING` and reverses the SNAT. It **rewrites the packet's destination port from `6081` back to `<ephemeral_port>`**.

5. **UDP Layer Receives Destination Port `<ephemeral_port>`:**
   The packet is delivered to the local UDP stack (`__udp4_lib_rcv`) with `dport = <ephemeral_port>`. Because the Geneve tunnel socket is listening on `6081` and **no socket is listening on the ephemeral port**, the kernel issues an **ICMP Port Unreachable (Type 3, Code 3)** error.

---

## How to Verify with Conntrack

Check the active conntrack entry for UDP 6081 on Site A:
```bash
sudo conntrack -L -p udp --dport 6081
```

You will see an entry showing the original source port was an ephemeral port mapped to `6081`.

---

## Solutions

### Option 1: Remove the `snat` Rule (Recommended)

Allow Geneve to use its standard ephemeral source ports:

1. **Find the handle number:**
   ```bash
   sudo nft -a list chain ip nat POSTROUTING
   ```

2. **Delete the rule by handle:**
   ```bash
   sudo nft delete rule ip nat POSTROUTING handle <handle_num>
   ```

3. **Or flush the table/chain if not used for other purposes:**
   ```bash
   sudo nft flush chain ip nat POSTROUTING
   # or
   sudo nft delete table ip nat
   ```

4. **Flush stale conntrack entries:**
   ```bash
   sudo conntrack -F
   ```

---

### Option 2: Stateless / TC eBPF Rewriting (If Fixed Source Port is Required)

If outbound Geneve packets must use source port `6081` without stateful conntrack reversing the destination port on incoming replies:
- Use an eBPF TC filter (such as `geneve-nat/udp-port-rewrite.c`) attached to the `clsact` qdisc.
- Or use a stateless `NOTRACK` rule in `raw` / `prerouting` to bypass Netfilter connection tracking entirely.
