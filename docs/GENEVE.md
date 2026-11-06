# GENEVE Deep Packet Inspection (DPI) & Evasion

## 1. How a GENEVE Packet is Recognized by DPI

A Deep Packet Inspection (DPI) engine identifies and decodes **GENEVE (Generic Network Virtualization Encapsulation)** packets ([RFC 8926](https://datatracker.ietf.org/doc/html/rfc8926)) by systematically inspecting outer transport headers, matching protocol signatures, and parsing the fixed and variable GENEVE header fields.

### Transport Layer Identification (Outer L4)
- **Outer Transport Protocol:** UDP (IP protocol `17`).
- **IANA-Assigned Port:** **`6081`** (Destination Port).
  - Most DPI engines trigger a GENEVE dissector when the UDP destination port is `6081`.
  - The source port is typically entropy-generated (hash of inner packet flows) to enable ECMP load balancing across intermediate network hardware.

### GENEVE Fixed Header Inspection
Once the UDP destination port matches (or heuristic inspection is enabled), the DPI engine validates the **8-byte fixed GENEVE header**:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Ver|  Opt Len  |O|C|    Rsvd   |          Protocol Type        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Virtual Network Identifier (VNI)       |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Variable-Length Options                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

DPI checks the following fields for validity:

1. **Version (`Ver`, 2 bits):**
   - Must be `0b00` (`0`). Packets with any other version are either malformed or belong to an unsupported specification.
2. **Options Length (`Opt Len`, 6 bits):**
   - Specifies the length of optional metadata fields in **4-byte multiples**, excluding the 8-byte base header.
   - Total GENEVE header length = `8 + (Opt Len * 4)` bytes.
   - The DPI engine verifies that `UDP Payload Length >= 8 + (Opt Len * 4)`.
3. **Control Flags:**
   - **`O` (OAM packet, 1 bit):** Indicates Operations, Administration, and Maintenance control packets.
   - **`C` (Critical options present, 1 bit):** Indicates that one or more TLV options are critical.
   - **`Rsvd` (Reserved, 6 bits):** Must be sent as zero. Checked for anomalies by DPI.
4. **Protocol Type (16 bits):**
   - Specifies the EtherType of the encapsulated inner frame (e.g., `0x6558` for Transparent Ethernet Bridging / standard Ethernet, `0x0800` for IPv4, `0x86DD` for IPv6).
   - Validating that this is a recognized EtherType helps prevent false positives.
5. **Virtual Network Identifier (`VNI`, 24 bits):**
   - Identifies the virtual network segment.
6. **Reserved (8 bits):**
   - Must be `0x00`.

### Variable-Length TLV Options Parsing
If `Opt Len > 0`, the DPI engine iterates through the TLV (Type-Length-Value) options:

```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Option Class         |      Type     |R|R|R| Length  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Variable Option Data                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Option Class (16 bits):** Identifies the vendor or standards body (e.g., `0x0108` for Linux OVS, `0x0100`–`0x01FF` allocated by OpenStack/IANA).
- **Type (8 bits):** High bit of `Type` indicates whether the option is critical (`C=1`).
- **Length (5 bits):** Length of option data in 4-byte multiples (excluding the 4-byte TLV header).
- **Validation:** The sum of all TLV lengths must match `Opt Len * 4`. A mismatch indicates fragmentation, truncation, or crafting anomalies.

### Inner Packet Decapsulation & Inspection
After skipping `8 + (Opt Len * 4)` bytes:
- If **Protocol Type is `0x6558`** (Transparent Ethernet Bridging): The payload starts with the **Inner Ethernet Header** (6-byte Dest MAC, 6-byte Src MAC, 2-byte Inner EtherType).
- If **Protocol Type is `0x0800` / `0x86DD`**: The payload directly contains an **Inner IPv4 / IPv6 header**.
- The DPI engine re-enters its standard L3/L4/L7 protocol decoders recursively on the inner payload.

### Summary of DPI Heuristic Checks

| Stage | Inspection Check | Expected Value |
| :--- | :--- | :--- |
| **L3** | IP Protocol | `17` (UDP) |
| **L4** | Destination UDP Port | `6081` |
| **GENEVE (Byte 0)** | Version (`bits 0-1`) | `0` (`0b00`) |
| **GENEVE (Bytes 2-3)** | Protocol Type | Recognized EtherType (e.g., `0x6558`, `0x0800`, `0x86DD`) |
| **GENEVE (Byte 7)** | Reserved field | `0x00` |
| **Length Check** | UDP Payload Size | `>= 8 + (Opt Len * 4) + Inner Header Size` |

---

## 2. Simplest Header Modification to Evade DPI Classification

The simplest and most effective change to the GENEVE header data to make DPI engines classify the packet as a **standard/unrecognized UDP payload** is to **set the `Version` (Ver) field to a non-zero value (e.g., `1`, `2`, or `3`)**.

### Why This Works
1. **RFC 8926 Compliance (Section 3.5):**
   > *"Version (Ver): 2 bits. The current version number is 0. Packets with any other version number MUST be treated as an unrecognized version and MUST be dropped by an end system or not decoded as GENEVE by middleboxes."*
2. **DPI Dissector Execution Flow:**
   - Standard DPI dissectors (e.g., Wireshark, Suricata, Zeek, Snort, hardware ASICs) inspect the first byte of the UDP payload when port `6081` is matched.
   - They check `(first_byte >> 6) == 0`.
   - If non-zero, the parser immediately bails out of the GENEVE dissector and classifies the packet as generic raw UDP data rather than parsing or flagging inner headers.

### Implementation
- **Location:** Byte 0 of the UDP payload (bits 0–1 of the GENEVE header).
- **Bitwise operation:**
  ```c
  geneve_hdr[0] |= 0x80; // Sets Version = 2 (0b10)
  // or
  geneve_hdr[0] |= 0x40; // Sets Version = 1 (0b01)
  ```

### Comparison With Other Header Modifications

| Header Field | Change | Why Version is Preferable |
| :--- | :--- | :--- |
| **`Version` (Bits 0–1)** | Set to non-zero (`0b01`, `0b10`, `0b11`) | **Best:** Universal and immediate dissector abort; treated as plain UDP payload. |
| **`Protocol Type` (Bytes 2–3)** | Set to `0x0000` or undefined EtherType | DPI engines still recognize the packet as GENEVE, but flag the inner payload as "Unknown/Malformed Protocol". |
| **`Opt Len` (Bits 2–7)** | Set to a value larger than UDP payload | Triggers a "Malformed / Truncated GENEVE Packet" alert instead of treating it as raw UDP. |
| **`Reserved` (Byte 7)** | Set to non-zero (`0xFF`) | Permissive DPI engines ignore reserved bits for backward compatibility and still dissect inner packets. |
