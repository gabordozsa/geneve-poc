# preprocess — TCP Proxy with Independent TLS

## Overview

`preprocess` is a single-process TCP proxy that sits between an incoming
client and an upstream server.  It accepts one connection at a time on a
local port, and forwards all data to a pre-established outgoing connection.

TLS can be enabled independently on each side:

| Flag | Side       | Effect                                              |
|------|------------|-----------------------------------------------------|
| `-L` | Local (in) | Accept incoming connections under TLS (server role) |
| `-R` | Remote (out)| Connect to the upstream server over TLS (client role)|

All four combinations are supported: plain↔plain, TLS↔plain, plain↔TLS,
and TLS↔TLS.

```
Client ──(plain or TLS)──► [preprocess :local_port] ──(plain or TLS)──► Upstream
                                 -L controls this side    -R controls this side
```

---

## Building

```bash
gcc -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2 -g \
    src/preprocess.c -o preprocess -lssl -lcrypto
```

Requires OpenSSL development headers (`libssl-dev` on Debian/Ubuntu,
`openssl-devel` on RHEL/Fedora).

To use certificate files at a non-default path, override at compile time:

```bash
gcc ... -DSERVER_CERT=\"/etc/myapp/cert.pem\" -DSERVER_KEY=\"/etc/myapp/key.pem\" \
    src/preprocess.c -o preprocess -lssl -lcrypto
```

---

## Command-Line Arguments

```
preprocess -l <local_port> -r <remote_ip> -p <remote_port> [-L] [-R]

Required:
  -l <port>   Local TCP port to listen on
  -r <ip>     Remote IPv4 or IPv6 address to connect to
  -p <port>   Remote TCP port to connect to

Optional:
  -L          Enable TLS for incoming connections (local side)
              Requires certs/server.crt and certs/server.key
  -R          Enable TLS for the outgoing connection (remote side)
  -h          Print this help and exit
```

### Argument Validation

| Argument | Constraint                              |
|----------|-----------------------------------------|
| `-l`     | 1 ≤ port ≤ 65535                        |
| `-r`     | Valid IPv4 or IPv6 address              |
| `-p`     | 1 ≤ port ≤ 65535                        |

---

## Generating Test Certificates

When using `-L`, the proxy needs a certificate and private key.  The
included helper script generates a self-signed CA and a server certificate
suitable for local testing:

```bash
./scripts/gen-certs.sh
```

Output written to `./certs/`:

```
certs/
├── ca.crt        Self-signed CA certificate
├── ca.key        CA private key
├── server.crt    Server certificate (signed by the local CA)
├── server.csr    Certificate signing request (intermediate artefact)
└── server.key    Server private key
```

By default `CN=localhost` with SANs for `localhost` and `127.0.0.1`.
Override via environment variables:

```bash
CN=192.168.1.10 DAYS=365 ./scripts/gen-certs.sh
```

---

## Usage Examples

### Plain proxy (no TLS on either side)

```bash
./preprocess -l 8080 -r 127.0.0.1 -p 9000
```

```
Client ──TCP──► :8080 [preprocess] ──TCP──► 127.0.0.1:9000
```

### TLS on the incoming side only (`-L`)

Useful when clients expect TLS but the upstream is plain TCP (e.g. a local
service that does not speak TLS).

```bash
./scripts/gen-certs.sh          # one-time cert generation
./preprocess -l 8443 -r 127.0.0.1 -p 9000 -L
```

```
Client ──TLS──► :8443 [preprocess] ──TCP──► 127.0.0.1:9000
```

Test with `openssl s_client`:

```bash
openssl s_client -connect 127.0.0.1:8443 -CAfile certs/ca.crt
```

### TLS on the outgoing side only (`-R`)

Useful as a TLS offload proxy: accept plain connections locally and forward
them encrypted to a remote TLS server.

```bash
./preprocess -l 8080 -r example.com -p 443 -R
```

```
Client ──TCP──► :8080 [preprocess] ──TLS──► example.com:443
```

> **Note:** when `-R` is used with self-signed test certificates, peer
> verification is disabled.  For production use, re-enable
> `SSL_VERIFY_PEER` in `tls_connect()` and provide a trusted CA bundle.

### TLS on both sides (`-L -R`)

```bash
./scripts/gen-certs.sh
./preprocess -l 8443 -r 127.0.0.1 -p 9443 -L -R
```

```
Client ──TLS──► :8443 [preprocess] ──TLS──► 127.0.0.1:9443
```

---

## How It Works

### Startup sequence

```
main()
  ├── parse_args()          validate CLI arguments
  ├── setup_signals()       register SIGINT/SIGTERM → clean shutdown
  ├── make_server_ctx()     load cert/key into SSL_CTX  (if -L)
  ├── connect_to_remote()   open TCP connection to remote_ip:remote_port
  ├── tls_connect()         TLS client handshake        (if -R)
  └── listen_on()           bind and listen on local_port
```

### Accept loop

```
while running:
    select(listen_fd, timeout=1s)   ← allows checking the running flag
    accept()                        ← new client connection
    tls_accept()                    ← TLS server handshake (if -L)
    relay_*()                       ← bidirectional forwarding until disconnect
    close client fd
```

### Relay variants

The relay function is chosen at runtime based on which sides use TLS:

| Local side | Remote side | Function           |
|------------|-------------|--------------------|
| plain      | plain       | `relay_plain_plain`|
| plain      | TLS         | `relay_plain_tls`  |
| TLS        | plain       | `relay_tls_plain`  |
| TLS        | TLS         | `relay_tls_tls`    |

All variants use `select()` for I/O multiplexing.  TLS variants use a 1-second
timeout so the `running` flag is checked regularly for clean shutdown.

### Shutdown

```
SIGINT / SIGTERM
    → running = 0
    → select() returns / times out
    → relay loop exits
    → SSL_free() / close() on all fds
    → exit(0)
```

---

## File Layout

```
geneve-poc/
├── PREPROCESS.md          ← this document
├── src/
│   └── preprocess.c       ← proxy source (standalone, no geneve.h dependency)
├── scripts/
│   └── gen-certs.sh       ← self-signed certificate generator
└── certs/                 ← generated certificate output (git-ignored)
    ├── ca.crt
    ├── server.crt
    └── server.key
```

---

## Known Limitations

- One upstream connection is shared across all incoming clients.  Each client
  is served sequentially; the next client is accepted only after the current
  one disconnects.
- IPv6 upstream is supported; the local listener binds IPv4 (`0.0.0.0`) only.
- Remote TLS peer verification is disabled in self-signed test mode.  Enable
  `SSL_VERIFY_PEER` and supply a CA bundle for production use.
- Single-threaded `select()`-based loop; suitable for low-concurrency
  pre-processing or testing scenarios.
