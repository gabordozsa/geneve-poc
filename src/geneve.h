/*
 * geneve.h — Geneve tunnel public API (RFC 8926)
 *
 * Structures, constants, and function prototypes shared by
 * geneve.c and main.c.
 */

#ifndef GENEVE_H
#define GENEVE_H

#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define GENEVE_PORT_DEFAULT   6081        /* IANA-assigned UDP port    */
#define GENEVE_VER            0           /* RFC 8926 §3.5: must be 0  */
#define GENEVE_HDR_MIN_LEN    8           /* fixed base header bytes   */

/* Inner EtherTypes */
#define ETHERTYPE_IPV4        0x0800
#define ETHERTYPE_IPV6        0x86DD
#define ETHERTYPE_ETH_FRAME   0x6558      /* transparent Ethernet      */

/* Buffer large enough for any legal IP datagram + Geneve overhead */
#define GENEVE_BUF_SIZE       65536

/* Maximum VNI value (24-bit field) */
#define GENEVE_VNI_MAX        0x00FFFFFFu

/* Default TUN interface name */
#define TUN_IFACE_DEFAULT     "tun0"

/* Default inner MTU */
#define INNER_MTU_DEFAULT     1450

/* ------------------------------------------------------------------ */
/* Geneve base header (RFC 8926 §3.4)                                  */
/* 8 bytes, packed, big-endian on wire.                                */
/* ------------------------------------------------------------------ */

typedef struct __attribute__((packed)) {
    /*
     * Byte 0:  [7:6] ver (must be 0)
     *          [5:0] opt_len (number of 4-byte option words that follow)
     */
    uint8_t  ver_optlen;

    /*
     * Byte 1:  [7] OAM (control/management frame)
     *          [6] critical options present
     *          [5:0] reserved (must be 0)
     */
    uint8_t  flags;

    /*
     * Bytes 2-3: inner payload EtherType (network byte order)
     */
    uint16_t proto_type;

    /*
     * Bytes 4-6: 24-bit Virtual Network Identifier (network byte order)
     */
    uint8_t  vni[3];

    /*
     * Byte 7: reserved (must be 0)
     */
    uint8_t  reserved;
} geneve_hdr_t;

/* Convenience macros for ver_optlen field */
#define GENEVE_VER_SHIFT      6
#define GENEVE_OPTLEN_MASK    0x3Fu
#define GENEVE_VER_MASK       0xC0u

/* Flags byte bitmasks */
#define GENEVE_FLAG_OAM       0x80u
#define GENEVE_FLAG_CRITICAL  0x40u

/* ------------------------------------------------------------------ */
/* Runtime configuration (populated from CLI)                          */
/* ------------------------------------------------------------------ */

typedef struct {
    char     local_addr[INET6_ADDRSTRLEN];  /* outer local address     */
    char     remote_addr[INET6_ADDRSTRLEN]; /* outer remote address    */
    uint32_t vni;                           /* 24-bit tunnel ID        */
    uint16_t port;                          /* outer UDP port          */
    char     tun_iface[IFNAMSIZ];           /* TUN device name         */
    uint16_t proto_type;                    /* inner EtherType         */
    int      mtu;                           /* inner MTU               */
    int      debug;                         /* verbose logging flag    */
} config_t;

/* ------------------------------------------------------------------ */
/* Live tunnel context                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    int                     tun_fd;        /* TUN device fd            */
    int                     sock_fd;       /* outer UDP socket fd      */
    struct sockaddr_storage remote_sa;     /* pre-resolved remote addr */
    socklen_t               remote_sa_len;
    config_t               *cfg;
} tunnel_ctx_t;

/* ------------------------------------------------------------------ */
/* Function prototypes                                                  */
/* ------------------------------------------------------------------ */

/*
 * Open (or create) the named TUN interface.
 * Returns fd on success, -1 on failure (errno set).
 */
int tun_open(const char *dev);

/*
 * Create and bind the outer UDP socket according to cfg.
 * Returns fd on success, -1 on failure.
 */
int socket_open(const config_t *cfg);

/*
 * Fill *hdr with a zero-option Geneve base header.
 */
void build_geneve_hdr(geneve_hdr_t *hdr, uint32_t vni, uint16_t proto_type);

/*
 * Prepend a Geneve header to 'payload' and send via ctx->sock_fd.
 * Returns bytes forwarded (Geneve hdr + payload) or -1.
 */
ssize_t encap_and_send(tunnel_ctx_t *ctx,
                       const uint8_t *payload, size_t plen);

/*
 * Receive one Geneve datagram, validate, strip header, write inner
 * payload to ctx->tun_fd.
 * Returns bytes written to TUN or -1.
 */
ssize_t decap_and_deliver(tunnel_ctx_t *ctx);

/*
 * Enter the select()-based forwarding loop.  Runs until 'running' == 0.
 */
void run_tunnel(tunnel_ctx_t *ctx);

/*
 * Register SIGINT/SIGTERM handlers that stop the event loop.
 */
void setup_signals(void);

#endif /* GENEVE_H */
