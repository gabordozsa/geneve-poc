/*
 * preprocess.c — TCP proxy with independent TLS on each side
 *
 * Responsibilities:
 *   - Parse and validate command-line arguments (getopt)
 *   - Open an outgoing TCP connection to remote_ip:remote_port
 *   - Optionally wrap the outgoing connection in TLS (-R, use_tls_remote)
 *   - Listen for incoming TCP connections on local_port
 *   - Optionally accept incoming connections under TLS (-L, use_tls_local)
 *   - Forward data bidirectionally between each accepted connection
 *     and the upstream connection
 *
 *   Control-byte framing (upstream channel):
 *   Every message sent over the upstream connection uses a 3-byte header:
 *     byte 0      — type: 0x00 DATA, 0x01 DISCONNECT
 *     bytes 1-2   — payload length (big-endian uint16, 0 for DISCONNECT)
 *   followed by exactly that many payload bytes.
 *
 *   The downstream (client-facing) side always sees plain, unframed data.
 *
 *   Framing is asymmetric across the proxy pair:
 *     -F  (use_framing)  on the CLIENT-side proxy: wraps every outgoing
 *         chunk in a frame header before sending upstream, and strips the
 *         frame header from data received from upstream.
 *     -S  (strip_framing) on the SERVER-side proxy: strips the frame header
 *         from data received from the client-side proxy (upstream direction)
 *         before forwarding to the real server.  Does NOT add frame headers
 *         to data going the other way (server → client proxy).
 *
 *   When the downstream connection closes, the -F proxy sends a DISCONNECT
 *   frame to the upstream peer.  If the upstream peer was started with -C
 *   (close_upstream) it tears down the upstream connection upon receiving
 *   that frame, triggering the normal reconnect logic.
 *
 *   Deferred upstream mode (-D, server-side proxy):
 *   With -D the upstream (backend) connection is NOT opened at startup.
 *   Instead it is opened on demand when the first DATA frame arrives from
 *   the downstream peer, and closed when a DISCONNECT frame is received.
 *   The downstream (inter-proxy) connection is kept alive across sessions.
 *   This allows the client-proxy ↔ server-proxy link to be permanent while
 *   the server-proxy ↔ backend connection is created/torn-down per request.
 *
 * Usage:
 *   preprocess -l <local_port> -r <remote_ip> -p <remote_port> [-L] [-R] [-F] [-S] [-C] [-D] [-n <name>]
 *
 *   -L  TLS on the listening (local) side — requires certs/server.crt + certs/server.key
 *   -R  TLS on the outgoing (remote) side — connects with TLS client
 *   -F  Enable control-byte framing on the upstream channel (client-side proxy)
 *   -S  Strip control-byte framing from upstream data (server-side proxy)
 *   -C  Close the upstream connection when a DISCONNECT control byte is received
 *   -D  Deferred upstream: connect to backend only when first data arrives,
 *       close backend on DISCONNECT frame (use on the server-side proxy with -S)
 *   -n  Name prefix used in log messages (default: "preprocess")
 *
 * Build (without modifying the main Makefile):
 *   gcc -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2 -g \
 *       src/preprocess.c -o preprocess -lssl -lcrypto
 *
 * Generate self-signed test certificates first:
 *   ./scripts/gen-certs.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define BUF_SIZE        16384       /* relay buffer (bytes)            */
#define LISTEN_BACKLOG  8           /* accept() queue depth            */

/* Default paths for the local-side TLS certificate and private key.
 * Override at compile time with -DSERVER_CERT="..." -DSERVER_KEY="..." */
#ifndef SERVER_CERT
#  define SERVER_CERT  "certs/server.crt"
#endif
#ifndef SERVER_KEY
#  define SERVER_KEY   "certs/server.key"
#endif

/* ------------------------------------------------------------------ */
/* Global running flag — cleared by SIGINT / SIGTERM                   */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t running = 1;

/* Log prefix — set from cfg.name after argument parsing              */
static const char *log_prefix = "preprocess";

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    uint16_t    local_port;                     /* port to listen on       */
    char        remote_ip[INET6_ADDRSTRLEN];    /* upstream host           */
    uint16_t    remote_port;                    /* upstream port           */
    int         use_tls_local;                  /* TLS on incoming side    */
    int         use_tls_remote;                 /* TLS on outgoing side    */
    int         use_framing;                    /* frame/deframe upstream channel (-F) */
    int         strip_framing;                  /* strip frames from upstream data (-S) */
    int         close_upstream;                 /* close upstream on DISCONNECT frame */
    int         deferred_upstream;              /* connect to backend on first data (-D) */
    char        name[64];                       /* log prefix (-n, default "preprocess") */
} proxy_cfg_t;

/* ------------------------------------------------------------------ */
/* Control-byte framing constants                                      */
/* ------------------------------------------------------------------ */

#define CTRL_DATA       0x00    /* normal data frame header            */
#define CTRL_DISCONNECT 0x01    /* downstream-closed notification      */

/* ------------------------------------------------------------------ */
/* Usage                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -l <local_port> -r <remote_ip> -p <remote_port> [-L] [-R] [-F] [-S] [-C] [-D] [-n <name>]\n"
        "\n"
        "Required:\n"
        "  -l <port>   Local TCP port to listen on\n"
        "  -r <ip>     Remote IP address to connect to\n"
        "  -p <port>   Remote TCP port to connect to\n"
        "\n"
        "Optional:\n"
        "  -L          Enable TLS for incoming connections (local side)\n"
        "              Requires " SERVER_CERT " and " SERVER_KEY "\n"
        "  -R          Enable TLS for the outgoing connection (remote side)\n"
        "  -F          Enable control-byte framing on the upstream channel\n"
        "              Use on the client-side proxy; do NOT use on the server-side\n"
        "  -S          Strip control-byte framing from data received from upstream\n"
        "              Use on the server-side proxy together with -D\n"
        "  -C          Close upstream connection when a DISCONNECT control byte\n"
        "              is received from the upstream peer\n"
        "  -D          Deferred upstream: open backend connection on first data,\n"
        "              close it on DISCONNECT (use on the server-side proxy with -S)\n"
        "  -n <name>   Name prefix for log messages (default: \"preprocess\")\n"
        "  -h          Print this help and exit\n",
        prog);
}

/* ------------------------------------------------------------------ */
/* Argument parsing                                                    */
/* ------------------------------------------------------------------ */

static int parse_args(int argc, char *argv[], proxy_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->name, "preprocess", sizeof(cfg->name) - 1);

    int local_set  = 0;
    int remote_set = 0;
    int port_set   = 0;

    int opt;
    while ((opt = getopt(argc, argv, "l:r:p:LRFSCDn:h")) != -1) {
        switch (opt) {

        case 'l': {
            char *end;
            errno = 0;
            unsigned long v = strtoul(optarg, &end, 10);
            if (errno != 0 || *end != '\0' || v == 0 || v > 65535) {
                fprintf(stderr, "error: local_port must be 1-65535\n");
                return -1;
            }
            cfg->local_port = (uint16_t)v;
            local_set = 1;
            break;
        }

        case 'r': {
            union { struct in_addr v4; struct in6_addr v6; } tmp;
            if (inet_pton(AF_INET,  optarg, &tmp.v4) != 1 &&
                inet_pton(AF_INET6, optarg, &tmp.v6) != 1) {
                fprintf(stderr, "error: '%s' is not a valid IP address\n",
                        optarg);
                return -1;
            }
            strncpy(cfg->remote_ip, optarg, sizeof(cfg->remote_ip) - 1);
            remote_set = 1;
            break;
        }

        case 'p': {
            char *end;
            errno = 0;
            unsigned long v = strtoul(optarg, &end, 10);
            if (errno != 0 || *end != '\0' || v == 0 || v > 65535) {
                fprintf(stderr, "error: remote_port must be 1-65535\n");
                return -1;
            }
            cfg->remote_port = (uint16_t)v;
            port_set = 1;
            break;
        }

        case 'L':
            cfg->use_tls_local = 1;
            break;

        case 'R':
            cfg->use_tls_remote = 1;
            break;

        case 'F':
            cfg->use_framing = 1;
            break;

        case 'S':
            cfg->strip_framing = 1;
            break;

        case 'C':
            cfg->close_upstream = 1;
            break;

        case 'D':
            cfg->deferred_upstream = 1;
            break;

        case 'n':
            strncpy(cfg->name, optarg, sizeof(cfg->name) - 1);
            cfg->name[sizeof(cfg->name) - 1] = '\0';
            break;

        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);

        default:
            usage(argv[0]);
            return -1;
        }
    }

    if (!local_set) {
        fprintf(stderr, "error: -l <local_port> is required\n");
        return -1;
    }
    if (!remote_set) {
        fprintf(stderr, "error: -r <remote_ip> is required\n");
        return -1;
    }
    if (!port_set) {
        fprintf(stderr, "error: -p <remote_port> is required\n");
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Outgoing TCP connection                                             */
/* ------------------------------------------------------------------ */

/*
 * connect_to_remote() — open a TCP connection to ip:port.
 * Tries IPv4 first, falls back to IPv6.
 * Returns connected socket fd on success, -1 on failure.
 */
static int connect_to_remote(const char *ip, uint16_t port)
{
    struct sockaddr_in sa4;
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
    sa4.sin_port   = htons(port);

    if (inet_pton(AF_INET, ip, &sa4.sin_addr) == 1) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { perror("socket(AF_INET)"); return -1; }
        if (connect(fd, (struct sockaddr *)&sa4, sizeof(sa4)) < 0) {
            perror("connect");
            close(fd);
            return -1;
        }
        return fd;
    }

    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port   = htons(port);

    if (inet_pton(AF_INET6, ip, &sa6.sin6_addr) == 1) {
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd < 0) { perror("socket(AF_INET6)"); return -1; }
        if (connect(fd, (struct sockaddr *)&sa6, sizeof(sa6)) < 0) {
            perror("connect");
            close(fd);
            return -1;
        }
        return fd;
    }

    fprintf(stderr, "error: could not resolve '%s' as IPv4 or IPv6\n", ip);
    return -1;
}

/* ------------------------------------------------------------------ */
/* TLS — outgoing (client) side                                        */
/* ------------------------------------------------------------------ */

/*
 * tls_connect() — wrap an already-connected fd in a TLS client session.
 *
 * For self-signed / test certificates the remote peer's cert is NOT
 * verified against the system CA bundle; pass verify_peer=1 in
 * production to re-enable chain verification.
 *
 * Returns a non-NULL SSL* on success.  The SSL object owns the fd and
 * will close it on SSL_free().
 */
static SSL *tls_connect(int fd, const char *hostname)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    /*
     * Self-signed test mode: skip certificate verification so the proxy
     * works out-of-the-box with the certs generated by gen-certs.sh.
     * Remove SSL_VERIFY_NONE and uncomment the two lines below to
     * enforce full chain validation in production.
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    /* SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);        */
    /* SSL_CTX_set_default_verify_paths(ctx);                 */

    SSL *ssl = SSL_new(ctx);
    SSL_CTX_free(ctx);
    if (!ssl) { ERR_print_errors_fp(stderr); return NULL; }

    SSL_set_tlsext_host_name(ssl, hostname);   /* SNI */

    if (SSL_set_fd(ssl, fd) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

/* ------------------------------------------------------------------ */
/* TLS — incoming (server) side                                        */
/* ------------------------------------------------------------------ */

/*
 * make_server_ctx() — build a server-side SSL_CTX loaded with the
 * certificate and private key pointed to by SERVER_CERT / SERVER_KEY.
 * Returns a new SSL_CTX* on success, NULL on failure.
 * Caller must SSL_CTX_free() it when done.
 */
static SSL_CTX *make_server_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "error: cannot load certificate '%s'\n", SERVER_CERT);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "error: cannot load private key '%s'\n", SERVER_KEY);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "error: certificate and private key do not match\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/*
 * tls_accept() — perform a TLS server handshake on an already-accepted fd.
 * Returns a non-NULL SSL* on success.  The SSL object owns the fd.
 */
static SSL *tls_accept(int fd, SSL_CTX *ctx)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { ERR_print_errors_fp(stderr); return NULL; }

    if (SSL_set_fd(ssl, fd) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    if (SSL_accept(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

/* ------------------------------------------------------------------ */
/* Local listening socket                                              */
/* ------------------------------------------------------------------ */

static int listen_on(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, LISTEN_BACKLOG) < 0) {
        perror("listen"); close(fd); return -1;
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/* Framed message struct                                               */
/* ------------------------------------------------------------------ */

/*
 * frame_t — the unit exchanged on the upstream channel.
 *
 * Wire format: [ctrl:1][len_hi:1][len_lo:1][payload:len]
 *   ctrl        — CTRL_DATA or CTRL_DISCONNECT
 *   len_hi/lo   — big-endian uint16 payload length (0 for DISCONNECT)
 *   data[]      — payload bytes, immediately following the 3-byte header
 *
 * Header and data live in a single contiguous struct so that a write or
 * read of (FRAME_HDR_SIZE + data_len) bytes covers the whole frame in
 * one I/O operation with no intermediate copies.
 */
typedef struct __attribute__((packed)) {
    uint8_t ctrl;
    uint8_t len_hi;
    uint8_t len_lo;
    uint8_t data[BUF_SIZE];
} frame_t;

#define FRAME_HDR_SIZE  3

/* ------------------------------------------------------------------ */
/* Low-level exact-read helpers                                        */
/* ------------------------------------------------------------------ */

/*
 * read_exact_plain() — read exactly n bytes from fd into buf.
 * Returns 0 on success, -1 on EOF or error.
 */
static int read_exact_plain(int fd, void *buf, size_t n)
{
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

/*
 * read_exact_ssl() — read exactly n bytes from ssl into buf.
 * Returns 0 on success, -1 on error.
 */
static int read_exact_ssl(SSL *ssl, void *buf, int n)
{
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        int r = SSL_read(ssl, p, n);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                ERR_print_errors_fp(stderr);
            return -1;
        }
        p += r; n -= r;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Framed write helpers                                                */
/* ------------------------------------------------------------------ */

/*
 * write_framed_plain() — write a framed message to fd in a single write().
 * Fills a frame_t (header + data contiguous), then writes
 * FRAME_HDR_SIZE + data_len bytes in one call.
 * data_len == 0 is valid for CTRL_DISCONNECT frames.
 * Returns 0 on success, -1 on error.
 */
static int write_framed_plain(int fd, uint8_t ctrl, const uint8_t *data, size_t data_len)
{
    frame_t frame;
    frame.ctrl   = ctrl;
    frame.len_hi = (uint8_t)(data_len >> 8);
    frame.len_lo = (uint8_t)(data_len & 0xff);
    if (data_len > 0)
        memcpy(frame.data, data, data_len);
    size_t total = FRAME_HDR_SIZE + data_len;
    if (write(fd, &frame, total) != (ssize_t)total) return -1;
    return 0;
}

/*
 * write_framed_ssl() — TLS equivalent of write_framed_plain().
 *
 * frame_buf must point to a buffer of at least FRAME_HDR_SIZE + data_len
 * bytes where the payload already sits at frame_buf[FRAME_HDR_SIZE].
 * The function writes the 3-byte header into frame_buf[0..2] in-place and
 * issues a single SSL_write() covering header + data — no memcpy needed.
 *
 * For DISCONNECT frames (data_len == 0) any buffer of >= FRAME_HDR_SIZE
 * bytes is sufficient; pass NULL payload via a dedicated header-only buffer.
 *
 * Returns 0 on success, -1 on error.
 */
static int write_framed_ssl(SSL *ssl, uint8_t ctrl, uint8_t *frame_buf, int data_len)
{
    frame_buf[0] = ctrl;
    frame_buf[1] = (uint8_t)((unsigned)data_len >> 8);
    frame_buf[2] = (uint8_t)(data_len & 0xff);
    int total = FRAME_HDR_SIZE + data_len;
    if (SSL_write(ssl, frame_buf, total) != total) return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Framed read helpers — strip framing from the downstream→upstream channel */
/* ------------------------------------------------------------------------ */

/*
 * read_result_t — outcome of reading one framed message.
 */
typedef enum {
    READ_OK         =  0,   /* DATA frame read; payload forwarded           */
    READ_DISCONNECT = -1,   /* DISCONNECT frame received                    */
    READ_ERROR      = -2,   /* I/O error                                    */
} read_result_t;

/*
 * read_framed_plain_to_plain() — server-side strip path (downstream→upstream).
 * Reads one complete frame from src_fd into a frame_t (header + data in a
 * single read), strips the header, and writes the raw payload to dst_fd.
 * Handles CTRL_DISCONNECT according to close_on_disconnect.
 */
static read_result_t read_framed_plain_to_plain(int src_fd, int dst_fd,
                                                int close_on_disconnect)
{
    frame_t frame;
    /* Read header first to learn the payload length */
    if (read_exact_plain(src_fd, &frame, FRAME_HDR_SIZE) < 0)
        return READ_ERROR;

    uint16_t data_len = ((uint16_t)frame.len_hi << 8) | frame.len_lo;

    if (frame.ctrl == CTRL_DISCONNECT) {
        fprintf(stderr, "%s: received DISCONNECT from downstream\n", log_prefix);
        return close_on_disconnect ? READ_DISCONNECT : READ_OK;
    }

    /* DATA frame: read payload into frame.data then forward in one write */
    if (data_len > 0) {
        if (read_exact_plain(src_fd, frame.data, data_len) < 0) return READ_ERROR;
        if (write(dst_fd, frame.data, data_len) != data_len) return READ_ERROR;
    }
    return READ_OK;
}

/*
 * read_framed_ssl_to_plain() — server-side strip path, TLS downstream.
 * Reads one complete frame from src_ssl into a frame_t (header + data),
 * strips the header, and writes the raw payload to dst_fd (plain backend).
 */
static read_result_t read_framed_ssl_to_plain(SSL *src_ssl, int dst_fd,
                                              int close_on_disconnect)
{
    frame_t frame;
    if (read_exact_ssl(src_ssl, &frame, FRAME_HDR_SIZE) < 0)
        return READ_ERROR;

    uint16_t data_len = ((uint16_t)frame.len_hi << 8) | frame.len_lo;

    if (frame.ctrl == CTRL_DISCONNECT) {
        fprintf(stderr, "%s: received DISCONNECT from downstream\n", log_prefix);
        return close_on_disconnect ? READ_DISCONNECT : READ_OK;
    }

    if (data_len > 0) {
        if (read_exact_ssl(src_ssl, frame.data, (int)data_len) < 0) return READ_ERROR;
        if (write(dst_fd, frame.data, data_len) != data_len) return READ_ERROR;
    }
    return READ_OK;
}

/*
 * read_framed_ssl_to_ssl() — server-side strip path, TLS on both sides.
 * Reads one complete frame from src_ssl into a frame_t (header + data),
 * strips the header, and writes the raw payload to dst_ssl (TLS backend).
 */
static read_result_t read_framed_ssl_to_ssl(SSL *src_ssl, SSL *dst_ssl,
                                            int close_on_disconnect)
{
    frame_t frame;
    if (read_exact_ssl(src_ssl, &frame, FRAME_HDR_SIZE) < 0)
        return READ_ERROR;

    uint16_t data_len = ((uint16_t)frame.len_hi << 8) | frame.len_lo;

    if (frame.ctrl == CTRL_DISCONNECT) {
        fprintf(stderr, "%s: received DISCONNECT from downstream\n", log_prefix);
        return close_on_disconnect ? READ_DISCONNECT : READ_OK;
    }

    if (data_len > 0) {
        if (read_exact_ssl(src_ssl, frame.data, (int)data_len) < 0) return READ_ERROR;
        if (SSL_write(dst_ssl, frame.data, (int)data_len) <= 0) {
            ERR_print_errors_fp(stderr);
            return READ_ERROR;
        }
    }
    return READ_OK;
}

/*
 * read_framed_plain_to_ssl() — server-side strip path, plain downstream, TLS upstream.
 * Reads one complete frame from src_fd into a frame_t (header + data),
 * strips the header, and writes the raw payload to dst_ssl (TLS backend).
 */
static read_result_t read_framed_plain_to_ssl(int src_fd, SSL *dst_ssl,
                                              int close_on_disconnect)
{
    frame_t frame;
    if (read_exact_plain(src_fd, &frame, FRAME_HDR_SIZE) < 0)
        return READ_ERROR;

    uint16_t data_len = ((uint16_t)frame.len_hi << 8) | frame.len_lo;

    if (frame.ctrl == CTRL_DISCONNECT) {
        fprintf(stderr, "%s: received DISCONNECT from downstream\n", log_prefix);
        return close_on_disconnect ? READ_DISCONNECT : READ_OK;
    }

    if (data_len > 0) {
        if (read_exact_plain(src_fd, frame.data, data_len) < 0) return READ_ERROR;
        if (SSL_write(dst_ssl, frame.data, (int)data_len) <= 0) {
            ERR_print_errors_fp(stderr);
            return READ_ERROR;
        }
    }
    return READ_OK;
}

/* ------------------------------------------------------------------ */
/* relay_closed_t                                                      */
/* ------------------------------------------------------------------ */

/*
 * relay_closed_t — which side caused the relay loop to exit.
 *
 * RELAY_DOWNSTREAM : the client-side connection closed (or errored).
 *                    The upstream connection is still good; keep it.
 * RELAY_UPSTREAM   : the upstream connection closed (or errored), or a
 *                    DISCONNECT frame was received with -C set.
 *                    The caller must reconnect before the next client.
 */
typedef enum {
    RELAY_DOWNSTREAM = 0,
    RELAY_UPSTREAM   = 1
} relay_closed_t;

/* ------------------------------------------------------------------ */
/* Four relay variants (local side × remote side)                     */
/* ------------------------------------------------------------------ */

/*
 * relay_plain_plain() — both sides are plain TCP.
 *
 * Framing is one-directional (downstream→upstream only):
 *   use_framing  (-F, client proxy): wrap outgoing data in a DATA frame;
 *                responses from upstream are always plain passthrough.
 *   strip_framing (-S, server proxy): incoming data from client_fd carries
 *                framing — read the frame, strip the ctrl byte, forward plain
 *                to upstream_fd; handle DISCONNECT with close_upstream.
 *                Responses from upstream_fd are always plain passthrough.
 */
static relay_closed_t relay_plain_plain(int client_fd, int upstream_fd,
                                        int use_framing, int strip_framing,
                                        int close_upstream)
{
    uint8_t buf[BUF_SIZE];
    int maxfd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;
    relay_closed_t reason = RELAY_DOWNSTREAM;

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd,   &rfds);
        FD_SET(upstream_fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        /* downstream → upstream */
        if (rc > 0 && FD_ISSET(client_fd, &rfds)) {
            if (use_framing) {
                /* client proxy: read plain, wrap in a DATA frame, send framed */
                ssize_t n = read(client_fd, buf, sizeof(buf));
                if (n <= 0) { reason = RELAY_DOWNSTREAM; break; }
                if (write_framed_plain(upstream_fd, CTRL_DATA, buf, (size_t)n) < 0) {
                    reason = RELAY_UPSTREAM; break;
                }
            } else if (strip_framing) {
                /* server proxy: read framed from client proxy, write plain to backend */
                read_result_t rr = read_framed_plain_to_plain(client_fd, upstream_fd,
                                                              close_upstream);
                if (rr == READ_DISCONNECT) { reason = RELAY_UPSTREAM; break; }
                if (rr == READ_ERROR)      { reason = RELAY_DOWNSTREAM; break; }
            } else {
                ssize_t n = read(client_fd, buf, sizeof(buf));
                if (n <= 0) { reason = RELAY_DOWNSTREAM; break; }
                if (write(upstream_fd, buf, (size_t)n) != n) {
                    reason = RELAY_UPSTREAM; break;
                }
            }
        }
        /* upstream → downstream — always plain passthrough */
        if (rc > 0 && FD_ISSET(upstream_fd, &rfds)) {
            ssize_t n = read(upstream_fd, buf, sizeof(buf));
            if (n <= 0) { reason = RELAY_UPSTREAM; break; }
            if (write(client_fd, buf, (size_t)n) != n) { reason = RELAY_DOWNSTREAM; break; }
        }
    }
    return reason;
}

/*
 * relay_plain_tls() — plain local client, TLS remote upstream.
 */
static relay_closed_t relay_plain_tls(int client_fd, SSL *upstream_ssl,
                                      int use_framing, int strip_framing,
                                      int close_upstream)
{
    uint8_t buf[FRAME_HDR_SIZE + BUF_SIZE];
    int upstream_fd = SSL_get_fd(upstream_ssl);
    int maxfd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;
    relay_closed_t reason = RELAY_DOWNSTREAM;

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd,   &rfds);
        FD_SET(upstream_fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        /* plain client → TLS upstream */
        if (rc > 0 && FD_ISSET(client_fd, &rfds)) {
            if (use_framing) {
                ssize_t n = read(client_fd, buf + FRAME_HDR_SIZE, BUF_SIZE);
                if (n <= 0) { reason = RELAY_DOWNSTREAM; break; }
                if (write_framed_ssl(upstream_ssl, CTRL_DATA, buf, (int)n) < 0) {
                    ERR_print_errors_fp(stderr);
                    reason = RELAY_UPSTREAM; break;
                }
            } else if (strip_framing) {
                /* server proxy with TLS upstream: plain downstream → TLS upstream */
                read_result_t rr = read_framed_plain_to_ssl(client_fd, upstream_ssl,
                                                            close_upstream);
                if (rr == READ_DISCONNECT) { reason = RELAY_UPSTREAM; break; }
                if (rr == READ_ERROR)      { reason = RELAY_DOWNSTREAM; break; }
            } else {
                ssize_t n = read(client_fd, buf, sizeof(buf));
                if (n <= 0) { reason = RELAY_DOWNSTREAM; break; }
                if (SSL_write(upstream_ssl, buf, (int)n) <= 0) {
                    ERR_print_errors_fp(stderr);
                    reason = RELAY_UPSTREAM; break;
                }
            }
        }

        /* TLS upstream → plain client — always plain passthrough */
        if (rc > 0 && FD_ISSET(upstream_fd, &rfds)) {
            int n = SSL_read(upstream_ssl, buf, BUF_SIZE);
            if (n <= 0) {
                int err = SSL_get_error(upstream_ssl, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                    ERR_print_errors_fp(stderr);
                reason = RELAY_UPSTREAM; break;
            }
            if (write(client_fd, buf, (size_t)n) != (ssize_t)n) {
                reason = RELAY_DOWNSTREAM; break;
            }
        }
    }
    return reason;
}

/*
 * relay_tls_plain() — TLS local client, plain remote upstream.
 */
static relay_closed_t relay_tls_plain(SSL *client_ssl, int upstream_fd,
                                      int use_framing, int strip_framing,
                                      int close_upstream)
{
    uint8_t buf[BUF_SIZE];
    int client_fd = SSL_get_fd(client_ssl);
    int maxfd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;
    relay_closed_t reason = RELAY_DOWNSTREAM;

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd,   &rfds);
        FD_SET(upstream_fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        /* TLS client → plain upstream */
        if (rc > 0 && FD_ISSET(client_fd, &rfds)) {
            if (use_framing) {
                int n = SSL_read(client_ssl, buf, sizeof(buf));
                if (n <= 0) {
                    int err = SSL_get_error(client_ssl, n);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                        ERR_print_errors_fp(stderr);
                    reason = RELAY_DOWNSTREAM; break;
                }
                if (write_framed_plain(upstream_fd, CTRL_DATA, buf, (size_t)n) < 0) {
                    reason = RELAY_UPSTREAM; break;
                }
            } else if (strip_framing) {
                read_result_t rr = read_framed_ssl_to_plain(client_ssl, upstream_fd,
                                                            close_upstream);
                if (rr == READ_DISCONNECT) { reason = RELAY_UPSTREAM; break; }
                if (rr == READ_ERROR)      { reason = RELAY_DOWNSTREAM; break; }
            } else {
                int n = SSL_read(client_ssl, buf, sizeof(buf));
                if (n <= 0) {
                    int err = SSL_get_error(client_ssl, n);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                        ERR_print_errors_fp(stderr);
                    reason = RELAY_DOWNSTREAM; break;
                }
                if (write(upstream_fd, buf, (size_t)n) != n) {
                    reason = RELAY_UPSTREAM; break;
                }
            }
        }

        /* plain upstream → TLS client — always plain passthrough */
        if (rc > 0 && FD_ISSET(upstream_fd, &rfds)) {
            ssize_t n = read(upstream_fd, buf, sizeof(buf));
            if (n <= 0) { reason = RELAY_UPSTREAM; break; }
            if (SSL_write(client_ssl, buf, (int)n) <= 0) {
                ERR_print_errors_fp(stderr);
                reason = RELAY_DOWNSTREAM; break;
            }
        }
    }
    return reason;
}

/*
 * relay_tls_tls() — TLS on both sides.
 */
static relay_closed_t relay_tls_tls(SSL *client_ssl, SSL *upstream_ssl,
                                    int use_framing, int strip_framing,
                                    int close_upstream)
{
    uint8_t buf[FRAME_HDR_SIZE + BUF_SIZE];
    int client_fd   = SSL_get_fd(client_ssl);
    int upstream_fd = SSL_get_fd(upstream_ssl);
    int maxfd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;
    relay_closed_t reason = RELAY_DOWNSTREAM;

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd,   &rfds);
        FD_SET(upstream_fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        /* TLS client → TLS upstream */
        if (rc > 0 && FD_ISSET(client_fd, &rfds)) {
            if (use_framing) {
                int n = SSL_read(client_ssl, buf + FRAME_HDR_SIZE, BUF_SIZE);
                if (n <= 0) {
                    int err = SSL_get_error(client_ssl, n);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                        ERR_print_errors_fp(stderr);
                    reason = RELAY_DOWNSTREAM; break;
                }
                if (write_framed_ssl(upstream_ssl, CTRL_DATA, buf, n) < 0) {
                    ERR_print_errors_fp(stderr);
                    reason = RELAY_UPSTREAM; break;
                }
            } else if (strip_framing) {
                read_result_t rr = read_framed_ssl_to_ssl(client_ssl, upstream_ssl,
                                                          close_upstream);
                if (rr == READ_DISCONNECT) { reason = RELAY_UPSTREAM; break; }
                if (rr == READ_ERROR)      { reason = RELAY_DOWNSTREAM; break; }
            } else {
                int n = SSL_read(client_ssl, buf, sizeof(buf));
                if (n <= 0) {
                    int err = SSL_get_error(client_ssl, n);
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                        ERR_print_errors_fp(stderr);
                    reason = RELAY_DOWNSTREAM; break;
                }
                if (SSL_write(upstream_ssl, buf, n) <= 0) {
                    ERR_print_errors_fp(stderr);
                    reason = RELAY_UPSTREAM; break;
                }
            }
        }

        /* TLS upstream → TLS client — always plain passthrough */
        if (rc > 0 && FD_ISSET(upstream_fd, &rfds)) {
            int n = SSL_read(upstream_ssl, buf, BUF_SIZE);
            if (n <= 0) {
                int err = SSL_get_error(upstream_ssl, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                    ERR_print_errors_fp(stderr);
                reason = RELAY_UPSTREAM; break;
            }
            if (SSL_write(client_ssl, buf, n) <= 0) {
                ERR_print_errors_fp(stderr);
                reason = RELAY_DOWNSTREAM; break;
            }
        }
    }
    return reason;
}

/* ------------------------------------------------------------------ */
/* Deferred-upstream relay (server-side -S -D)                        */
/* ------------------------------------------------------------------ */

/*
 * relay_deferred_plain() — server-side relay with deferred backend connect.
 *
 * The downstream (inter-proxy) connection represented by client_fd stays
 * open for the lifetime of this function.  For each logical session:
 *
 *   1. Wait for a framed DATA frame on client_fd.
 *   2. On first DATA: open a plain TCP connection to remote_ip:remote_port.
 *   3. Relay framed DATA frames → plain bytes to backend, plain bytes from
 *      backend → written back to client_fd unframed.
 *   4. On DISCONNECT frame (or backend close): close the backend socket,
 *      then loop back to step 1 for the next session.
 *
 * Returns when client_fd closes or a fatal error occurs.
 *
 * NOTE: use_tls_remote is handled by relay_deferred_ssl() below.
 */
static void relay_deferred_plain(int client_fd, SSL *client_ssl,
                                 const char *remote_ip, uint16_t remote_port,
                                 int use_tls_remote, SSL_CTX *remote_ctx_unused)
{
    (void)remote_ctx_unused;
    frame_t frame;

    while (running) {
        /* ---- Phase 1: idle — wait for the first DATA frame ---- */
        int backend_fd   = -1;
        SSL *backend_ssl = NULL;

        while (running && backend_fd < 0) {
            /* Read the 3-byte header into the frame struct */
            int rd = client_ssl
                ? read_exact_ssl(client_ssl, &frame, FRAME_HDR_SIZE)
                : read_exact_plain(client_fd,  &frame, FRAME_HDR_SIZE);
            if (rd < 0)
                return;  /* downstream closed / error */

            uint16_t data_len = ((uint16_t)frame.len_hi << 8) | frame.len_lo;

            if (frame.ctrl == CTRL_DISCONNECT) {
                /* DISCONNECT while idle: no backend to close, just log */
                fprintf(stderr, "%s: received DISCONNECT (idle — no backend)\n",
                        log_prefix);
                continue;
            }

            /* DATA frame: open backend connection now */
            fprintf(stderr, "%s: first data received — connecting to backend %s:%u\n",
                    log_prefix, remote_ip, remote_port);
            backend_fd = connect_to_remote(remote_ip, remote_port);
            if (backend_fd < 0) {
                fprintf(stderr, "%s: backend connect failed — discarding %u bytes\n",
                        log_prefix, data_len);
                /* drain the payload so framing stays in sync */
                if (data_len > 0) {
                    int r = client_ssl
                        ? read_exact_ssl(client_ssl, frame.data, (int)data_len)
                        : read_exact_plain(client_fd,  frame.data, data_len);
                    if (r < 0) return;
                }
                continue;
            }

            /* Optionally wrap backend in TLS */
            if (use_tls_remote) {
                backend_ssl = tls_connect(backend_fd, remote_ip);
                if (!backend_ssl) {
                    fprintf(stderr, "%s: backend TLS handshake failed\n", log_prefix);
                    close(backend_fd);
                    backend_fd = -1;
                    /* drain payload */
                    if (data_len > 0) {
                        int r = client_ssl
                            ? read_exact_ssl(client_ssl, frame.data, (int)data_len)
                            : read_exact_plain(client_fd,  frame.data, data_len);
                        if (r < 0) return;
                    }
                    continue;
                }
                fprintf(stderr, "%s: backend TLS established (%s)\n",
                        log_prefix, SSL_get_cipher(backend_ssl));
            }

            /* Read the first frame's payload then forward it to the backend */
            if (data_len > 0) {
                int r = client_ssl
                    ? read_exact_ssl(client_ssl, frame.data, (int)data_len)
                    : read_exact_plain(client_fd,  frame.data, data_len);
                if (r < 0) {
                    if (backend_ssl) SSL_free(backend_ssl); else close(backend_fd);
                    return;
                }
                int wr = backend_ssl
                    ? SSL_write(backend_ssl, frame.data, (int)data_len)
                    : (int)write(backend_fd,  frame.data, data_len);
                if (wr <= 0) {
                    fprintf(stderr, "%s: backend write failed\n", log_prefix);
                    if (backend_ssl) SSL_free(backend_ssl); else close(backend_fd);
                    backend_fd  = -1;
                    backend_ssl = NULL;
                }
            }
            /* backend_fd may have been reset above on write failure */
        }

        if (!running) break;
        if (backend_fd < 0) continue;  /* backend connect failed, retry session */

        /* ---- Phase 2: active — relay until DISCONNECT or close ---- */
        int b_fd = backend_ssl ? SSL_get_fd(backend_ssl) : backend_fd;
        int c_fd = client_ssl  ? SSL_get_fd(client_ssl)  : client_fd;
        int maxfd = (c_fd > b_fd ? c_fd : b_fd) + 1;
        int session_done = 0;

        while (running && !session_done) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(c_fd, &rfds);
            FD_SET(b_fd, &rfds);
            struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

            int rc = select(maxfd, &rfds, NULL, NULL, &tv);
            if (rc < 0) {
                if (errno == EINTR) continue;
                perror("select");
                session_done = 1;
                break;
            }

            /* downstream (inter-proxy) → backend: framed DATA or DISCONNECT */
            if (rc > 0 && FD_ISSET(c_fd, &rfds)) {
                int rd = client_ssl
                    ? read_exact_ssl(client_ssl, &frame, FRAME_HDR_SIZE)
                    : read_exact_plain(client_fd,  &frame, FRAME_HDR_SIZE);
                if (rd < 0) {
                    /* inter-proxy connection closed — clean up and exit */
                    if (backend_ssl) SSL_free(backend_ssl); else close(backend_fd);
                    return;
                }

                uint16_t data_len = ((uint16_t)frame.len_hi << 8) | frame.len_lo;

                if (frame.ctrl == CTRL_DISCONNECT) {
                    fprintf(stderr, "%s: received DISCONNECT — closing backend\n",
                            log_prefix);
                    if (backend_ssl) SSL_free(backend_ssl); else close(backend_fd);
                    backend_fd  = -1;
                    backend_ssl = NULL;
                    session_done = 1;
                    break;
                }

                /* DATA: read payload into frame.data then forward to backend */
                if (data_len > 0) {
                    int r = client_ssl
                        ? read_exact_ssl(client_ssl, frame.data, (int)data_len)
                        : read_exact_plain(client_fd,  frame.data, data_len);
                    if (r < 0) {
                        if (backend_ssl) SSL_free(backend_ssl); else close(backend_fd);
                        return;
                    }
                    int wr = backend_ssl
                        ? SSL_write(backend_ssl, frame.data, (int)data_len)
                        : (int)write(backend_fd,  frame.data, data_len);
                    if (wr <= 0) {
                        fprintf(stderr, "%s: backend write error\n", log_prefix);
                        if (backend_ssl) SSL_free(backend_ssl); else close(backend_fd);
                        backend_fd  = -1;
                        backend_ssl = NULL;
                        session_done = 1;
                    }
                }
            }

            /* backend → downstream (inter-proxy): plain passthrough */
            if (rc > 0 && !session_done && FD_ISSET(b_fd, &rfds)) {
                int n;
                if (backend_ssl) {
                    n = SSL_read(backend_ssl, frame.data, sizeof(frame.data));
                    if (n <= 0) {
                        int err = SSL_get_error(backend_ssl, n);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                            ERR_print_errors_fp(stderr);
                        n = 0;
                    }
                } else {
                    n = (int)read(backend_fd, frame.data, sizeof(frame.data));
                    if (n < 0) n = 0;
                }
                if (n == 0) {
                    fprintf(stderr, "%s: backend closed connection\n", log_prefix);
                    if (backend_ssl) SSL_free(backend_ssl); else close(backend_fd);
                    backend_fd  = -1;
                    backend_ssl = NULL;
                    session_done = 1;
                    break;
                }
                int wr = client_ssl
                    ? SSL_write(client_ssl, frame.data, n)
                    : (int)write(client_fd,  frame.data, n);
                if (wr <= 0) {
                    /* inter-proxy link died */
                    if (backend_ssl) SSL_free(backend_ssl); else close(backend_fd);
                    return;
                }
            }
        }
        /* session_done: loop back to Phase 1 for the next curl request */
    }
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    proxy_cfg_t cfg;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    log_prefix = cfg.name;

    /* Register clean-shutdown signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* -------------------------------------------------------------- */
    /* Step 1: build server SSL_CTX if local TLS is requested         */
    /* -------------------------------------------------------------- */

    SSL_CTX *server_ctx = NULL;
    if (cfg.use_tls_local) {
        server_ctx = make_server_ctx();
        if (!server_ctx) {
            fprintf(stderr, "%s: failed to initialise local TLS context\n"
                            "  Run ./scripts/gen-certs.sh to create test certs\n",
                            log_prefix);
            return EXIT_FAILURE;
        }
        fprintf(stderr, "%s: local TLS enabled (cert=%s key=%s)\n",
                log_prefix, SERVER_CERT, SERVER_KEY);
    }

    /* -------------------------------------------------------------- */
    /* Step 2: open initial upstream connection (skipped with -D)     */
    /* -------------------------------------------------------------- */

    /* upstream_connect() — (re)open the upstream TCP+optional-TLS connection.
     * Returns 1 on success, 0 on failure.  On success *fd_out and *ssl_out
     * (may be NULL if !use_tls_remote) are set. */
#define upstream_connect(fd_out, ssl_out) __extension__({                   \
    int _ok = 0;                                                            \
    fprintf(stderr, "%s: connecting to %s:%u%s ...\n",                     \
            log_prefix, cfg.remote_ip, cfg.remote_port,                    \
            cfg.use_tls_remote ? " (TLS)" : "");                            \
    int _fd = connect_to_remote(cfg.remote_ip, cfg.remote_port);            \
    if (_fd < 0) {                                                          \
        fprintf(stderr, "%s: upstream connect failed\n", log_prefix);      \
    } else if (cfg.use_tls_remote) {                                        \
        SSL *_s = tls_connect(_fd, cfg.remote_ip);                          \
        if (!_s) {                                                          \
            fprintf(stderr, "%s: remote TLS handshake failed\n",           \
                    log_prefix);                                             \
            close(_fd);                                                     \
        } else {                                                            \
            fprintf(stderr, "%s: remote TLS established (%s)\n",           \
                    log_prefix, SSL_get_cipher(_s));                        \
            *(fd_out) = _fd; *(ssl_out) = _s; _ok = 1;                     \
        }                                                                   \
    } else {                                                                \
        *(fd_out) = _fd; *(ssl_out) = NULL; _ok = 1;                       \
    }                                                                       \
    _ok;                                                                    \
})

    int  upstream_fd  = -1;
    SSL *upstream_ssl = NULL;

    if (!cfg.deferred_upstream) {
        if (!upstream_connect(&upstream_fd, &upstream_ssl)) {
            if (server_ctx) SSL_CTX_free(server_ctx);
            return EXIT_FAILURE;
        }
    }

    /* -------------------------------------------------------------- */
    /* Step 3: listen for incoming TCP connections on local_port      */
    /* -------------------------------------------------------------- */

    int listen_fd = listen_on(cfg.local_port);
    if (listen_fd < 0) {
        if (upstream_ssl) SSL_free(upstream_ssl);
        else if (upstream_fd >= 0) close(upstream_fd);
        if (server_ctx) SSL_CTX_free(server_ctx);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "%s: listening on 0.0.0.0:%u%s\n",
            log_prefix, cfg.local_port, cfg.use_tls_local ? " (TLS)" : "");

    /* -------------------------------------------------------------- */
    /* Step 4: accept loop — one client at a time                     */
    /*                                                                 */
    /* Deferred mode (-D):                                             */
    /*   The accepted connection (from the client proxy) is handed to  */
    /*   relay_deferred_plain() which keeps it alive across multiple   */
    /*   backend sessions.  relay_deferred_plain() only returns when   */
    /*   the inter-proxy connection itself closes.  We then loop back  */
    /*   to accept the next inter-proxy connection.                    */
    /*                                                                 */
    /* Normal mode:                                                    */
    /*   The upstream connection is kept open across clients.  If the  */
    /*   upstream closes, reconnect before accepting the next client.  */
    /* -------------------------------------------------------------- */

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int rc = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }
        if (rc == 0) continue;  /* timeout — re-check running */

        struct sockaddr_storage peer_sa;
        socklen_t peer_len = sizeof(peer_sa);
        int client_fd = accept(listen_fd, (struct sockaddr *)&peer_sa, &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept"); break;
        }

        /* Log peer address */
        char peer_str[INET6_ADDRSTRLEN] = "<unknown>";
        uint16_t peer_port = 0;
        if (peer_sa.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&peer_sa;
            inet_ntop(AF_INET, &s->sin_addr, peer_str, sizeof(peer_str));
            peer_port = ntohs(s->sin_port);
        } else if (peer_sa.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&peer_sa;
            inet_ntop(AF_INET6, &s->sin6_addr, peer_str, sizeof(peer_str));
            peer_port = ntohs(s->sin6_port);
        }
        fprintf(stderr, "%s: accepted connection from %s:%u\n",
                log_prefix, peer_str, peer_port);

        /* Optionally perform TLS handshake on the incoming connection */
        SSL *client_ssl = NULL;
        if (cfg.use_tls_local) {
            client_ssl = tls_accept(client_fd, server_ctx);
            if (!client_ssl) {
                fprintf(stderr,
                        "%s: local TLS handshake failed with %s:%u\n",
                        log_prefix, peer_str, peer_port);
                close(client_fd);
                continue;
            }
            fprintf(stderr, "%s: local TLS handshake ok (%s) with %s:%u\n",
                    log_prefix, SSL_get_cipher(client_ssl), peer_str, peer_port);
        }

        if (cfg.deferred_upstream) {
            /* -D mode: relay_deferred_plain() owns this connection until
             * the inter-proxy link closes; it handles all backend sessions. */
            relay_deferred_plain(client_fd, client_ssl,
                                 cfg.remote_ip, cfg.remote_port,
                                 cfg.use_tls_remote, NULL);
            fprintf(stderr, "%s: inter-proxy connection from %s:%u closed\n",
                    log_prefix, peer_str, peer_port);
            if (client_ssl) SSL_free(client_ssl); else close(client_fd);
            /* Loop back to accept the next inter-proxy connection */
            continue;
        }

        /* Normal mode: relay — pick the right variant based on TLS config */
        relay_closed_t closed;
        if (!client_ssl && !upstream_ssl)
            closed = relay_plain_plain(client_fd, upstream_fd,
                                       cfg.use_framing, cfg.strip_framing,
                                       cfg.close_upstream);
        else if (!client_ssl &&  upstream_ssl)
            closed = relay_plain_tls(client_fd, upstream_ssl,
                                     cfg.use_framing, cfg.strip_framing,
                                     cfg.close_upstream);
        else if ( client_ssl && !upstream_ssl)
            closed = relay_tls_plain(client_ssl, upstream_fd,
                                     cfg.use_framing, cfg.strip_framing,
                                     cfg.close_upstream);
        else
            closed = relay_tls_tls(client_ssl, upstream_ssl,
                                   cfg.use_framing, cfg.strip_framing,
                                   cfg.close_upstream);

        fprintf(stderr, "%s: connection from %s:%u closed (%s)\n",
                log_prefix, peer_str, peer_port,
                closed == RELAY_UPSTREAM ? "upstream closed" : "downstream closed");

        /* Notify upstream that the downstream connection is gone (framing only) */
        if (cfg.use_framing && closed == RELAY_DOWNSTREAM) {
            fprintf(stderr, "%s: sending DISCONNECT to upstream\n", log_prefix);
            if (upstream_ssl) {
                uint8_t hdr[FRAME_HDR_SIZE];
                write_framed_ssl(upstream_ssl, CTRL_DISCONNECT, hdr, 0);
            }
            else
                write_framed_plain(upstream_fd, CTRL_DISCONNECT, NULL, 0);
        }

        if (client_ssl) SSL_free(client_ssl); else close(client_fd);

        /* If the upstream side closed, reconnect before the next accept */
        if (closed == RELAY_UPSTREAM) {
            if (upstream_ssl) SSL_free(upstream_ssl); else close(upstream_fd);
            upstream_fd  = -1;
            upstream_ssl = NULL;
            /* Retry until we reconnect or are asked to shut down */
            while (running && !upstream_connect(&upstream_fd, &upstream_ssl))
                sleep(1);
        }
    }

    /* -------------------------------------------------------------- */
    /* Cleanup                                                         */
    /* -------------------------------------------------------------- */

    close(listen_fd);
    if (upstream_ssl) SSL_free(upstream_ssl); else if (upstream_fd >= 0) close(upstream_fd);
    if (server_ctx)
        SSL_CTX_free(server_ctx);

    fprintf(stderr, "%s: shut down cleanly\n", log_prefix);
    return EXIT_SUCCESS;
}
