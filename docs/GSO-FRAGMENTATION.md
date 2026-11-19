# GSO and UDP Fragmentation

## Overview

Linux supports Generic Segmentation Offload (GSO) for UDP traffic, but **how** it handles large payloads (such as a 64KB payload) depends on whether you are using **standard UDP sending** (producing IP fragments) or the modern **UDP GSO (`UDP_SEGMENT`) API** (producing independent UDP datagrams).

---

## 1. Standard UDP Socket (`sendto` / `sendmsg` without `UDP_SEGMENT`)

When sending a single 64KB UDP datagram using a standard UDP socket:

* **Kernel behavior:** The kernel performs standard **IP fragmentation** in software.
* **Output on the wire:** Multiple IP fragments sharing the same IP ID. Only the **first** fragment contains the 8-byte UDP header; subsequent fragments are raw IP payload fragments (`More Fragments = 1`, `Fragment Offset > 0`).
* **Is GSO applied? No.**
  * *Note:* Linux historically had **UFO (UDP Fragmentation Offload)** to offload IP fragmentation to the NIC, but UFO was deprecated and removed in kernel **v4.14** due to architectural and driver maintenance issues.

---

## 2. Modern UDP GSO (`UDP_SEGMENT` / USO)

Introduced in **Linux 4.18**, Linux added true **UDP GSO** (and corresponding hardware offload **USO - UDP Segmentation Offload**).

* **How it works:** A payload up to 64KB is passed via `sendmsg()` along with a target segment size (e.g., 1400 bytes) configured via the `UDP_SEGMENT` socket option or ancillary control message (`cmsg`).
* **Output on the wire:** The single 64KB buffer is split by the kernel's GSO layer or the NIC into **multiple full, independent UDP datagrams**, each with its **own IP header and UDP header**.
* **Is GSO applied? Yes.** The kernel processes only one `sk_buff` through the entire networking stack/eBPF layer and defers segmentation to right before transmission (or directly onto the NIC hardware if USO is supported).

---

## Summary Comparison

| Feature | Standard UDP (64KB payload) | UDP GSO / `UDP_SEGMENT` |
| :--- | :--- | :--- |
| **Output Type** | 1 big UDP datagram split into **IP Fragments** | Multiple **distinct UDP packets** |
| **Headers on Wire** | 1 UDP header (1st packet only) + IP fragments | Complete **IP + UDP headers on every packet** |
| **Reassembly** | Receiver IP stack reassembles into 1 datagram | Receiver receives multiple separate UDP packets |
| **GSO Layer / Hardware Offload** | None (software IP fragmentation) | Handled by GSO / NIC USO hardware offload |
| **Typical Use Cases** | Legacy protocols, simple UDP datagrams | QUIC, WebRTC, high-throughput tunneling |

---

## Sending Traffic in `UDP_SEGMENT` Mode

Yes, but not with plain `nc`. `UDP_SEGMENT` is a socket option (`SOL_UDP`, value 103) or a `sendmsg()` control message. `nc` never sets it, so you need a small program or a tool that supports it. The kernel must be 4.18 or newer.

### Option 1: `iperf3`

```bash
iperf3 -c <ip> -u -b 0 -l 60000 --gso --gso-dg-size 1400   # needs a recent iperf3 build
```

Check `iperf3 --help | grep -i gso`, because support depends on the build.

### Option 2: a small C program

Set the option once on the socket:

```c
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

int main(int argc, char **argv)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int gso_size = 1400;                       /* payload bytes per datagram */
    setsockopt(s, SOL_UDP, UDP_SEGMENT, &gso_size, sizeof(gso_size));

    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(9999) };
    inet_pton(AF_INET, argv[1], &d.sin_addr);

    static char buf[60000];                    /* <= 65507 and <= 64 segments */
    memset(buf, 'A', sizeof(buf));
    sendto(s, buf, sizeof(buf), 0, (void *)&d, sizeof(d));
    close(s);
    return 0;
}
```

To set the size per call instead, pass a `cmsg` with `cmsg_level = SOL_UDP` and `cmsg_type = UDP_SEGMENT` holding a `uint16_t`.

### Option 3: Python

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(17, 103, 1400)            # SOL_UDP, UDP_SEGMENT
s.sendto(b"A" * 60000, ("<ip>", 9999))
```

### Limits

* The payload can be at most 65507 bytes. It is split into at most 64 segments (`UDP_MAX_SEGMENTS`).
* The segment size must fit within the path MTU minus the IP and UDP headers. Otherwise `sendmsg` fails with `EINVAL`.
* The last segment can be shorter than the others.
* If the egress device lacks `tx-udp-segmentation`, the kernel segments in software at the end of the stack. The result on the wire is the same. Check with `ethtool -k <dev> | grep udp-segmentation`.
* A TC hook on egress sees a single GSO `sk_buff` that is larger than the MTU, with `gso_size` set. The packets are only split after the hook. XDP on the receiver sees the individual datagrams.

### Verification

Run `tcpdump -ni <dev> udp port 9999` on the receiver. You should see many 1400-byte datagrams, not IP fragments. Run it on the sender's egress too. If it shows 64KB frames, you captured before segmentation.
