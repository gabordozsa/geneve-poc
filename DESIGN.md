# Geneve Tunnel — Design Document

## 1. Overview

This application implements a **Geneve** (Generic Network Virtualization
Encapsulation, RFC 8926) tunnel endpoint in userspace.  It runs as a single
process that forwards traffic between a local network interface and a remote
Geneve peer, supporting both **UDP** and **TCP** inner traffic.

```
Inner traffic (UDP or TCP)
        │
        ▼
┌────────────────────────────────┐
│        Geneve Header           │  outer UDP/IP transport
│  (VNI, options, protocol type) │
└────────────────────────────────┘
        │
        ▼
     Raw socket  →  Remote peer
```

The application operates in two complementary modes:

| Mode         | Description                                                  |
|--------------|--------------------------------------------------------------|
| **encap**    | Read inner frames from a TUN/TAP device, wrap in Geneve/UDP, send to remote peer |
| **decap**    | Listen for Geneve/UDP datagrams from remote peer, strip the header, write inner frames back to TUN/TAP |

Both directions run concurrently using a `select()`-based event loop.

---

## 2. Geneve Protocol Summary (RFC 8926)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────────────────────────────────────┤
│Ver│  Opt Len  │O│C│   Rsvd  │          Protocol Type            │
├─────────────────────────────────────────────────────────────────┤
│                Virtual Network Identifier (VNI)       │  Rsvd   │
├─────────────────────────────────────────────────────────────────┤
│                   Variable-Length Options ...                   │
└─────────────────────────────────────────────────────────────────┘
```

- **Ver** (2 bits): must be 0.
- **Opt Len** (6 bits): length of options in 4-byte words.
- **O** (1 bit): OAM frame.
- **C** (1 bit): critical options present.
- **Protocol Type** (16 bits): inner EtherType (0x0800 = IPv4, 0x86DD = IPv6,
  0x6558 = Ethernet frame).
- **VNI** (24 bits): Virtual Network Identifier.
- Default UDP destination port: **6081**.

---

## 3. Command-Line Arguments

```
geneve [OPTIONS]

Required:
  -l <addr>      Local IP address to bind (outer transport)
  -r <addr>      Remote peer IP address
  -v <vni>       Virtual Network Identifier (24-bit, 1–16777215)

Optional:
  -p <port>      UDP port for Geneve (default: 6081)
  -i <iface>     TUN device name (default: tun0)
  -t <type>      Inner protocol: "udp" | "tcp" | "eth" (default: udp)
                   udp  → EtherType 0x0800, IP+UDP payload
                   tcp  → EtherType 0x0800, IP+TCP payload
                   eth  → EtherType 0x6558, raw Ethernet frame
  -m <mtu>       Inner MTU (default: 1450)
  -d             Enable debug logging
  -h             Print usage and exit
```

### Argument Validation Rules

| Argument | Constraint                              |
|----------|-----------------------------------------|
| `-l`     | Must be a valid IPv4 or IPv6 address    |
| `-r`     | Must be a valid IPv4 or IPv6 address    |
| `-v`     | 1 ≤ VNI ≤ 0xFFFFFF                      |
| `-p`     | 1 ≤ port ≤ 65535                        |
| `-m`     | 576 ≤ MTU ≤ 65535                       |

---

## 4. Data Structures

### 4.1 `geneve_hdr_t`

Fixed 8-byte base header (options follow immediately):

```c
typedef struct __attribute__((packed)) {
    uint8_t  ver_optlen;   /* [7:6]=ver, [5:0]=opt_len (×4 bytes)   */
    uint8_t  flags;        /* [7]=OAM, [6]=critical, [5:0]=reserved  */
    uint16_t proto_type;   /* inner EtherType, network byte order     */
    uint8_t  vni[3];       /* 24-bit VNI, network byte order          */
    uint8_t  reserved;
} geneve_hdr_t;
```

### 4.2 `config_t`

Runtime configuration populated from CLI:

```c
typedef struct {
    char     local_addr[INET6_ADDRSTRLEN];
    char     remote_addr[INET6_ADDRSTRLEN];
    uint32_t vni;
    uint16_t port;
    char     tun_iface[IFNAMSIZ];
    uint16_t proto_type;   /* EtherType of inner payload              */
    int      mtu;
    int      debug;
} config_t;
```

### 4.3 `tunnel_ctx_t`

Live tunnel context holding open file descriptors:

```c
typedef struct {
    int          tun_fd;      /* TUN/TAP device fd                    */
    int          sock_fd;     /* UDP socket fd (outer transport)      */
    struct sockaddr_storage remote_sa;  /* pre-built remote address   */
    socklen_t    remote_sa_len;
    config_t    *cfg;
} tunnel_ctx_t;
```

---

## 5. Major Functions

### 5.1 `parse_args()`

```
int parse_args(int argc, char *argv[], config_t *cfg)
```

- Uses `getopt()` to walk the argument list.
- Populates `cfg` fields, applying defaults.
- Returns 0 on success, −1 on invalid/missing arguments.

### 5.2 `tun_open()`

```
int tun_open(const char *dev)
```

- Opens `/dev/net/tun` (Linux) with `IFF_TUN | IFF_NO_PI`.
- Returns the fd; caller must close on exit.
- Sets the interface up via `ioctl(TUNSETIFF)`.

### 5.3 `socket_open()`

```
int socket_open(const config_t *cfg)
```

- Creates a `SOCK_DGRAM` socket (AF_INET or AF_INET6 depending on address family).
- Binds to `local_addr:port`.
- Sets `SO_REUSEADDR`.
- Returns the fd.

### 5.4 `build_geneve_hdr()`

```
void build_geneve_hdr(geneve_hdr_t *hdr, uint32_t vni, uint16_t proto_type)
```

- Fills the fixed 8-byte header with `ver=0`, `opt_len=0`, no options.
- Encodes VNI into the three VNI bytes in network byte order.
- Sets `proto_type` in network byte order.

### 5.5 `encap_and_send()`

```
ssize_t encap_and_send(tunnel_ctx_t *ctx, const uint8_t *payload, size_t plen)
```

1. Prepend an 8-byte `geneve_hdr_t` to the payload using a scatter-gather
   `struct iovec` / `sendmsg()`.
2. Send the resulting datagram to `ctx->remote_sa` via the UDP socket.
3. Returns bytes sent (excluding outer UDP/IP headers) or −1 on error.

**UDP inner traffic path:**

```
TUN read → raw IP packet (IP+UDP)
         → build_geneve_hdr(proto_type=0x0800)
         → sendmsg() with iov[0]=geneve_hdr, iov[1]=IP packet
```

**TCP inner traffic path:**

```
TUN read → raw IP packet (IP+TCP)
         → build_geneve_hdr(proto_type=0x0800)
         → sendmsg() with iov[0]=geneve_hdr, iov[1]=IP packet
         (same encapsulation; TCP/UDP distinction is in the IP header)
```

> Note: from Geneve's perspective UDP and TCP inner traffic differ only in
> the IP protocol field inside the payload.  Both use EtherType 0x0800.
> The `−t udp|tcp` option controls which EtherType/log label is used and
> enforces an optional protocol-field filter during decap.

### 5.6 `decap_and_deliver()`

```
ssize_t decap_and_deliver(tunnel_ctx_t *ctx)
```

1. `recvfrom()` into a scratch buffer.
2. Validate minimum length (≥ 8 bytes for base header).
3. Check `ver` field is 0; drop and log if not.
4. Parse `opt_len` to skip variable options.
5. Optionally validate `proto_type` against configured EtherType.
6. Write inner payload to `ctx->tun_fd`.
7. Returns bytes written or −1 on error.

### 5.7 `run_tunnel()`

```
void run_tunnel(tunnel_ctx_t *ctx)
```

Main event loop:

```
while (running) {
    FD_SET(tun_fd, &rset);
    FD_SET(sock_fd, &rset);
    select(maxfd + 1, &rset, NULL, NULL, NULL);

    if FD_ISSET(tun_fd)  → read inner frame → encap_and_send()
    if FD_ISSET(sock_fd) → decap_and_deliver()
}
```

- `running` is a `volatile sig_atomic_t` set to 0 by a `SIGINT`/`SIGTERM`
  handler to allow clean shutdown.

### 5.8 `setup_signals()`

```
void setup_signals(void)
```

- Registers `SIGINT` and `SIGTERM` handlers that set `running = 0`.

---

## 6. Execution Flow

### 6.1 Startup

```
main()
  ├── parse_args()           validate and populate config_t
  ├── setup_signals()        register SIGINT/SIGTERM
  ├── tun_open()             open TUN device
  ├── socket_open()          create & bind UDP socket
  ├── build remote sockaddr  (getaddrinfo on remote_addr:port)
  └── run_tunnel()           enter event loop
```

### 6.2 UDP Inner Traffic — Encapsulation

```
[Inner host sends UDP datagram to TUN interface]
         │
         ▼
    tun_fd readable
         │
    read(tun_fd, buf, MTU)
         │
    build_geneve_hdr(vni, 0x0800)
         │
    sendmsg(sock_fd, iov={hdr, buf}, remote_sa)
         │
    [Geneve/UDP datagram leaves local host → remote peer]
```

### 6.3 TCP Inner Traffic — Encapsulation

```
[Inner host sends TCP segment to TUN interface]
         │
         ▼
    tun_fd readable
         │
    read(tun_fd, buf, MTU)       ← IP packet with proto=TCP
         │
    build_geneve_hdr(vni, 0x0800)
         │
    sendmsg(sock_fd, iov={hdr, buf}, remote_sa)
         │                       ← identical outer path to UDP case
    [Geneve/UDP datagram leaves local host → remote peer]
```

### 6.4 Decapsulation (any inner protocol)

```
[Remote peer sends Geneve/UDP datagram]
         │
         ▼
    sock_fd readable
         │
    recvfrom(sock_fd, buf, BUF_SIZE)
         │
    validate geneve_hdr (ver==0, length sane)
         │
    skip options  (opt_len × 4 bytes)
         │
    [optional] check proto_type matches configured EtherType
         │
    write(tun_fd, inner_payload, inner_len)
         │
    [Inner packet delivered to TUN interface → local network stack]
```

### 6.5 Shutdown

```
SIGINT / SIGTERM
    → running = 0
    → select() returns EINTR
    → loop exits
    → close(tun_fd), close(sock_fd)
    → exit(0)
```

---

## 7. Error Handling Strategy

| Situation                          | Action                                      |
|------------------------------------|---------------------------------------------|
| `tun_open()` fails                 | `perror()` + `exit(1)`                      |
| `socket_open()` fails              | `perror()` + `exit(1)`                      |
| `read()` on TUN returns error      | Log warning, continue loop (transient I/O)  |
| `sendmsg()` returns error          | Log warning (`errno`), continue loop        |
| `recvfrom()` returns error         | Log warning, continue loop                  |
| Bad Geneve version field           | Log and drop datagram                       |
| Datagram shorter than 8 bytes      | Log and drop datagram                       |
| `write()` to TUN fails             | Log warning, continue loop                  |
| `select()` interrupted (EINTR)     | Check `running` flag, exit cleanly if 0     |

---

## 8. Buffer Sizing

```
BUF_SIZE = MTU + sizeof(geneve_hdr_t) + 60  /* max IP options */
                                           + 8  /* outer UDP header */
         ≈ 1450 + 8 + 60 + 8 = 1526 bytes
```

A static `uint8_t buf[65536]` is used to accommodate any legal IP packet.

---

## 9. File Layout

```
geneve-poc/
├── DESIGN.md          ← this document
├── Makefile
├── src/
│   ├── geneve.h       ← public API: structs, constants, prototypes
│   ├── geneve.c       ← encap / decap / tunnel logic
│   └── main.c         ← CLI, startup, signal handling
```

---

## 10. Known Limitations / Future Work

- IPv6 outer transport is structurally supported but not tested.
- No Geneve options (opt_len is always 0 on transmit; received options are skipped).
- No DTLS/TLS over the outer UDP channel.
- No MTU path discovery; assumes fixed inner MTU.
- Single-threaded; `select()` is sufficient for proof-of-concept throughput.
