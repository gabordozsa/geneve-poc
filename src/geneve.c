/*
 * geneve.c — Core Geneve tunnel logic (RFC 8926)
 *
 * Implements:
 *   tun_open()        — open/create a Linux TUN interface
 *   socket_open()     — create & bind the outer UDP socket
 *   build_geneve_hdr()— fill the 8-byte Geneve base header
 *   encap_and_send()  — read from TUN, encapsulate, send via UDP
 *   decap_and_deliver()— receive UDP datagram, strip Geneve, write to TUN
 *   run_tunnel()      — select()-based event loop
 *   setup_signals()   — SIGINT/SIGTERM → clean shutdown
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>          /* struct iovec, sendmsg */

#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "geneve.h"

/* ------------------------------------------------------------------ */
/* Module-level running flag — written by signal handler               */
/* ------------------------------------------------------------------ */

volatile sig_atomic_t running = 1;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * Log a debug message when cfg->debug is set.
 */
static void dbg(const config_t *cfg, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void dbg(const config_t *cfg, const char *fmt, ...)
{
    if (!cfg->debug)
        return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[geneve] ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* Signal handler                                                      */
/* ------------------------------------------------------------------ */

static void sig_handler(int signum)
{
    (void)signum;
    running = 0;
}

void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;            /* do NOT set SA_RESTART so select() wakes */

    if (sigaction(SIGINT,  &sa, NULL) < 0 ||
        sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

/* ------------------------------------------------------------------ */
/* TUN device                                                          */
/* ------------------------------------------------------------------ */

/*
 * Open the TUN interface named by 'dev'.  If the interface does not
 * yet exist it is created.  IFF_NO_PI suppresses the 4-byte flags/
 * protocol prefix so we get a raw IP packet on each read().
 *
 * Requires CAP_NET_ADMIN (i.e. root or suitable capability).
 */
int tun_open(const char *dev)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open(/dev/net/tun)");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }

    return fd;
}

/* ------------------------------------------------------------------ */
/* UDP socket                                                          */
/* ------------------------------------------------------------------ */

/*
 * Create an AF_INET or AF_INET6 SOCK_DGRAM socket, set SO_REUSEADDR,
 * and bind to cfg->local_addr : cfg->port.
 */
int socket_open(const config_t *cfg)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;        /* IPv4 or IPv6              */
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_PASSIVE | AI_NUMERICHOST;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", cfg->port);

    int rc = getaddrinfo(cfg->local_addr, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n",
                cfg->local_addr, gai_strerror(rc));
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
        perror("setsockopt(SO_REUSEADDR)");  /* non-fatal */

    if (bind(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("bind");
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}

/*
 * Resolve the remote address and fill ctx->remote_sa / remote_sa_len.
 * Called once during startup.
 */
static int resolve_remote(tunnel_ctx_t *ctx)
{
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_NUMERICHOST;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", ctx->cfg->port);

    int rc = getaddrinfo(ctx->cfg->remote_addr, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(remote %s): %s\n",
                ctx->cfg->remote_addr, gai_strerror(rc));
        return -1;
    }

    if (res->ai_addrlen > sizeof(ctx->remote_sa)) {
        fprintf(stderr, "remote address too large\n");
        freeaddrinfo(res);
        return -1;
    }

    memcpy(&ctx->remote_sa, res->ai_addr, res->ai_addrlen);
    ctx->remote_sa_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Geneve header construction                                          */
/* ------------------------------------------------------------------ */

/*
 * Fill *hdr with a minimal Geneve base header (no options).
 *
 *   ver     = 0  (RFC 8926 mandates this)
 *   opt_len = 0  (no TLV options)
 *   flags   = 0  (not OAM, no critical options)
 *   proto   = proto_type  (inner EtherType, host-to-network conversion done here)
 *   vni     = vni  (24-bit, big-endian encoding)
 *   reserved= 0
 */
void build_geneve_hdr(geneve_hdr_t *hdr, uint32_t vni, uint16_t proto_type)
{
    memset(hdr, 0, sizeof(*hdr));
    /* ver=0, opt_len=0 → byte 0 is 0x00 */
    hdr->ver_optlen = (GENEVE_VER << GENEVE_VER_SHIFT) & GENEVE_VER_MASK;
    hdr->flags      = 0;
    hdr->proto_type = htons(proto_type);
    /* VNI occupies 24 bits; store in big-endian order */
    hdr->vni[0] = (uint8_t)((vni >> 16) & 0xFF);
    hdr->vni[1] = (uint8_t)((vni >>  8) & 0xFF);
    hdr->vni[2] = (uint8_t)( vni        & 0xFF);
    hdr->reserved = 0;
}

/* ------------------------------------------------------------------ */
/* Encapsulation: TUN → Geneve/UDP                                     */
/* ------------------------------------------------------------------ */

/*
 * Read one packet from ctx->tun_fd, prepend a Geneve header, and send
 * the resulting datagram to the remote peer.
 *
 * Inner traffic type (UDP, TCP, or raw Ethernet) is transparent at this
 * layer — it is fully contained in the IP packet read from the TUN device.
 * The EtherType in the Geneve header signals the payload type to the peer:
 *
 *   0x0800  — IPv4 packet (carries UDP or TCP in its payload)
 *   0x86DD  — IPv6 packet
 *   0x6558  — raw Ethernet frame
 *
 * Uses sendmsg() with a 2-element iovec to avoid a memcpy of the payload.
 */
ssize_t encap_and_send(tunnel_ctx_t *ctx,
                       const uint8_t *payload, size_t plen)
{
    geneve_hdr_t hdr;
    build_geneve_hdr(&hdr, ctx->cfg->vni, ctx->cfg->proto_type);

    struct iovec iov[2];
    iov[0].iov_base = &hdr;
    iov[0].iov_len  = sizeof(hdr);
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len  = plen;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name    = (void *)&ctx->remote_sa;
    msg.msg_namelen = ctx->remote_sa_len;
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 2;

    ssize_t sent = sendmsg(ctx->sock_fd, &msg, 0);
    if (sent < 0) {
        if (errno != EINTR)
            perror("sendmsg");
        return -1;
    }

    dbg(ctx->cfg,
        "encap: sent %zd bytes (hdr=%zu + payload=%zu) proto=0x%04X vni=%u",
        sent, sizeof(hdr), plen, ctx->cfg->proto_type, ctx->cfg->vni);

    return sent;
}

/* ------------------------------------------------------------------ */
/* Decapsulation: Geneve/UDP → TUN                                     */
/* ------------------------------------------------------------------ */

/*
 * Receive one UDP datagram on ctx->sock_fd.
 *
 * Validation steps:
 *   1. Datagram must be at least GENEVE_HDR_MIN_LEN bytes.
 *   2. The 'ver' field (top 2 bits of byte 0) must be 0.
 *   3. opt_len encodes how many 4-byte option words follow the fixed header;
 *      skip them to find the start of the inner payload.
 *   4. Optionally check proto_type matches the configured EtherType.
 *
 * The inner payload is then written to ctx->tun_fd, which delivers it
 * to the local network stack.  Whether the payload contains a UDP or TCP
 * datagram is determined by the IP protocol field inside the payload; the
 * kernel handles it transparently once we write the raw IP packet to the
 * TUN device.
 */
ssize_t decap_and_deliver(tunnel_ctx_t *ctx)
{
    static uint8_t buf[GENEVE_BUF_SIZE];

    struct sockaddr_storage src_sa;
    socklen_t src_sa_len = sizeof(src_sa);

    ssize_t rlen = recvfrom(ctx->sock_fd, buf, sizeof(buf), 0,
                            (struct sockaddr *)&src_sa, &src_sa_len);
    if (rlen < 0) {
        if (errno != EINTR)
            perror("recvfrom");
        return -1;
    }

    /* ---- 1. Minimum length check ---- */
    if (rlen < GENEVE_HDR_MIN_LEN) {
        fprintf(stderr, "geneve: datagram too short (%zd bytes), dropped\n",
                rlen);
        return -1;
    }

    const geneve_hdr_t *hdr = (const geneve_hdr_t *)buf;

    /* ---- 2. Version check ---- */
    uint8_t ver = (hdr->ver_optlen & GENEVE_VER_MASK) >> GENEVE_VER_SHIFT;
    if (ver != GENEVE_VER) {
        fprintf(stderr,
                "geneve: unsupported version %u, dropped\n", ver);
        return -1;
    }

    /* ---- 3. Skip variable-length options ---- */
    size_t opt_bytes = (size_t)(hdr->ver_optlen & GENEVE_OPTLEN_MASK) * 4;
    size_t hdr_total = GENEVE_HDR_MIN_LEN + opt_bytes;

    if ((size_t)rlen < hdr_total) {
        fprintf(stderr,
                "geneve: opt_len=%zu exceeds datagram (%zd), dropped\n",
                opt_bytes, rlen);
        return -1;
    }

    /* ---- 4. Optional EtherType check ---- */
    uint16_t rx_proto = ntohs(hdr->proto_type);
    if (rx_proto != ctx->cfg->proto_type) {
        /*
         * Log but do not drop — a peer may legitimately send a different
         * EtherType (e.g. IPv6 on a configured-for-IPv4 tunnel).  The
         * kernel will sort it out once the packet hits the TUN device.
         */
        dbg(ctx->cfg,
            "decap: proto mismatch rx=0x%04X cfg=0x%04X (delivering anyway)",
            rx_proto, ctx->cfg->proto_type);
    }

    /* ---- Extract VNI for debug logging ---- */
    uint32_t rx_vni = ((uint32_t)hdr->vni[0] << 16) |
                      ((uint32_t)hdr->vni[1] <<  8) |
                       (uint32_t)hdr->vni[2];

    const uint8_t *inner   = buf + hdr_total;
    size_t         inner_len = (size_t)rlen - hdr_total;

    dbg(ctx->cfg,
        "decap: rx %zd bytes, vni=%u proto=0x%04X inner=%zu bytes",
        rlen, rx_vni, rx_proto, inner_len);

    if (inner_len == 0) {
        /* Nothing to forward */
        return 0;
    }

    /* ---- Write inner packet to TUN device ---- */
    ssize_t written = write(ctx->tun_fd, inner, inner_len);
    if (written < 0) {
        if (errno != EINTR)
            perror("write(tun)");
        return -1;
    }

    return written;
}

/* ------------------------------------------------------------------ */
/* Event loop                                                          */
/* ------------------------------------------------------------------ */

/*
 * run_tunnel() — select()-based bidirectional forwarding loop.
 *
 * Monitors two file descriptors simultaneously:
 *   ctx->tun_fd   — inner packets from the local network stack
 *   ctx->sock_fd  — incoming Geneve datagrams from the remote peer
 *
 * Each readable event triggers either encap_and_send() or
 * decap_and_deliver().  The loop exits when 'running' is cleared by
 * the signal handler.
 */
void run_tunnel(tunnel_ctx_t *ctx)
{
    static uint8_t tun_buf[GENEVE_BUF_SIZE];
    int maxfd = (ctx->tun_fd > ctx->sock_fd)
                ? ctx->tun_fd : ctx->sock_fd;

    if (resolve_remote(ctx) < 0)
        exit(EXIT_FAILURE);

    fprintf(stderr,
            "geneve: tunnel up  local=%s  remote=%s  vni=%u  port=%u\n",
            ctx->cfg->local_addr, ctx->cfg->remote_addr,
            ctx->cfg->vni, ctx->cfg->port);

    while (running) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(ctx->tun_fd,  &rset);
        FD_SET(ctx->sock_fd, &rset);

        int nready = select(maxfd + 1, &rset, NULL, NULL, NULL);

        if (nready < 0) {
            if (errno == EINTR)
                continue;       /* woken by signal — re-check running  */
            perror("select");
            break;
        }

        /* ---- Inner → outer (encapsulation) ---- */
        if (FD_ISSET(ctx->tun_fd, &rset)) {
            ssize_t n = read(ctx->tun_fd, tun_buf, ctx->cfg->mtu);
            if (n < 0) {
                if (errno != EINTR)
                    perror("read(tun)");
            } else if (n > 0) {
                if (encap_and_send(ctx, tun_buf, (size_t)n) < 0) {
                    /*
                     * Transient send error (e.g. ENETUNREACH); log and
                     * continue rather than tearing down the tunnel.
                     */
                    fprintf(stderr,
                            "geneve: encap_and_send failed, continuing\n");
                }
            }
        }

        /* ---- Outer → inner (decapsulation) ---- */
        if (FD_ISSET(ctx->sock_fd, &rset)) {
            if (decap_and_deliver(ctx) < 0) {
                /* Transient receive or TUN write error; continue. */
                fprintf(stderr,
                        "geneve: decap_and_deliver failed, continuing\n");
            }
        }
    }

    fprintf(stderr, "geneve: shutting down\n");
    close(ctx->tun_fd);
    close(ctx->sock_fd);
}
