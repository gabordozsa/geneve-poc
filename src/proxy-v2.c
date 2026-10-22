/*
 * proxy-v2.c — multi-port TCP proxy with independent TLS on each side
 *
 * Extends proxy.c with a range of listening ports:
 *
 *   The proxy listens on  local_port, local_port+1, ..., local_port+num_ports-1.
 *   A client that connects to local_port+i is forwarded to
 *   remote_ip:(remote_port+i) over a NEW upstream connection that is opened
 *   when the client connects (upstream connections are always deferred, so
 *   there is no -D option).  Each accepted client is served by its own child
 *   process, so connections on different ports (or several on the same port)
 *   are relayed concurrently.  When either side closes, the other side is
 *   closed too.
 *
 *   TLS flags work as in proxy.c:
 *     -L  TLS on the listening (local) side — certs/server.crt + certs/server.key
 *     -R  TLS on the outgoing (remote) side — connects as TLS client
 *
 * Usage:
 *   proxy-v2 -l <local_port> -r <remote_ip> -p <remote_port> [-N <num_ports>]
 *            [-L] [-R] [-n <name>] [-G]
 *
 *   -N  Number of consecutive ports to serve (num_ports, default 1)
 *   -G  Debug logging
 *   -F/-S/-C are accepted and ignored for command-line compatibility.
 *
 * Build:
 *   gcc -Wall -Wextra -std=c11 -D_GNU_SOURCE -O2 -g \
 *       src/proxy-v2.c -o proxy-v2 -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

static int Debug;

#define BUF_SIZE        16384
#define LISTEN_BACKLOG  128

#ifndef SERVER_CERT
#  define SERVER_CERT  "certs/server.crt"
#endif
#ifndef SERVER_KEY
#  define SERVER_KEY   "certs/server.key"
#endif

static volatile sig_atomic_t running = 1;
static const char *log_prefix = "proxy-v2";

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

typedef struct {
    uint16_t    local_port;                     /* first port to listen on */
    uint16_t    num_ports;                      /* number of ports         */
    char        remote_ip[INET6_ADDRSTRLEN];    /* upstream host           */
    uint16_t    remote_port;                    /* first upstream port     */
    int         use_tls_local;                  /* TLS on incoming side    */
    int         use_tls_remote;                 /* TLS on outgoing side    */
    char        name[64];                       /* log prefix              */
} proxy_cfg_t;

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s -l <local_port> -r <remote_ip> -p <remote_port> [-N <num_ports>] [-L] [-R] [-n <name>] [-G]\n"
        "\n"
        "Required:\n"
        "  -l <port>   First local TCP port to listen on\n"
        "  -r <ip>     Remote IP address to connect to\n"
        "  -p <port>   First remote TCP port to connect to\n"
        "\n"
        "Optional:\n"
        "  -N <num>    num_ports: listen on local_port .. local_port+num-1; a client of\n"
        "              local_port+i is forwarded to remote_port+i (default 1)\n"
        "  -L          Enable TLS for incoming connections (local side)\n"
        "              Requires " SERVER_CERT " and " SERVER_KEY "\n"
        "  -R          Enable TLS for the outgoing connections (remote side)\n"
        "  -n <name>   Name prefix for log messages (default: \"proxy-v2\")\n"
        "  -G          Debug logging\n"
        "  -h          Print this help and exit\n",
        prog);
}

static int parse_port(const char *s, const char *what, uint16_t *out)
{
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || *end != '\0' || v == 0 || v > 65535) {
        fprintf(stderr, "error: %s must be 1-65535\n", what);
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

static int parse_args(int argc, char *argv[], proxy_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->name, "proxy-v2", sizeof(cfg->name) - 1);
    cfg->num_ports = 1;

    int local_set = 0, remote_set = 0, port_set = 0;

    int opt;
    while ((opt = getopt(argc, argv, "l:r:p:N:LRFSCGn:h")) != -1) {
        switch (opt) {
        case 'l':
            if (parse_port(optarg, "local_port", &cfg->local_port) < 0) return -1;
            local_set = 1;
            break;
        case 'r': {
            union { struct in_addr v4; struct in6_addr v6; } tmp;
            if (inet_pton(AF_INET,  optarg, &tmp.v4) != 1 &&
                inet_pton(AF_INET6, optarg, &tmp.v6) != 1) {
                fprintf(stderr, "error: '%s' is not a valid IP address\n", optarg);
                return -1;
            }
            strncpy(cfg->remote_ip, optarg, sizeof(cfg->remote_ip) - 1);
            remote_set = 1;
            break;
        }
        case 'p':
            if (parse_port(optarg, "remote_port", &cfg->remote_port) < 0) return -1;
            port_set = 1;
            break;
        case 'N': {
            char *end;
            errno = 0;
            unsigned long v = strtoul(optarg, &end, 10);
            if (errno != 0 || *end != '\0' || v == 0 || v > 65535) {
                fprintf(stderr, "error: num_ports must be 1-65535\n");
                return -1;
            }
            cfg->num_ports = (uint16_t)v;
            break;
        }
        case 'L': cfg->use_tls_local  = 1; break;
        case 'R': cfg->use_tls_remote = 1; break;
        case 'F': case 'S': case 'C':       /* ignored legacy options */
            break;
        case 'G': Debug = 1; break;
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

    if (!local_set)  { fprintf(stderr, "error: -l <local_port> is required\n");  return -1; }
    if (!remote_set) { fprintf(stderr, "error: -r <remote_ip> is required\n");   return -1; }
    if (!port_set)   { fprintf(stderr, "error: -p <remote_port> is required\n"); return -1; }

    if ((unsigned)cfg->local_port + cfg->num_ports - 1 > 65535) {
        fprintf(stderr, "error: local_port + num_ports - 1 exceeds 65535\n");
        return -1;
    }
    if ((unsigned)cfg->remote_port + cfg->num_ports - 1 > 65535) {
        fprintf(stderr, "error: remote_port + num_ports - 1 exceeds 65535\n");
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
/* ------------------------------------------------------------------ */
/* relay_closed_t                                                      */
/* ------------------------------------------------------------------ */

/*
 * relay_closed_t — which side caused the relay loop to exit.
 *
 * RELAY_DOWNSTREAM : the client-side connection closed (or errored).
 *                    The upstream connection is still good; keep it.
 * RELAY_UPSTREAM   : the upstream connection closed (or errored).
 *                    The caller must reconnect before the next client.
 */
typedef enum {
    RELAY_DOWNSTREAM = 0,
    RELAY_UPSTREAM   = 1
} relay_closed_t;

/* ------------------------------------------------------------------ */
/* Four relay variants (local side × remote side)                     */
/* ------------------------------------------------------------------ */

static relay_closed_t relay_plain_plain(int client_fd, int upstream_fd)
{
    uint8_t buf[BUF_SIZE];
    int maxfd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;
    relay_closed_t reason = RELAY_DOWNSTREAM;

    struct timespec last_downstream;
    clock_gettime(CLOCK_MONOTONIC, &last_downstream);

    while (running) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - last_downstream.tv_sec) +
                         (now.tv_nsec - last_downstream.tv_nsec) / 1e9;
        if (elapsed >= 1.0) {
            if (Debug) {
                fprintf(stderr, "%s: downstream timeout (1s)\n", log_prefix);
            }
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd,   &rfds);
        FD_SET(upstream_fd, &rfds);

        double remaining = 1.0 - elapsed;
        if (remaining < 0.0) remaining = 0.0;
        struct timeval tv;
        tv.tv_sec = (time_t)remaining;
        tv.tv_usec = (suseconds_t)((remaining - tv.tv_sec) * 1000000);

        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        /* downstream → upstream */
        if (rc > 0 && FD_ISSET(client_fd, &rfds)) {
            ssize_t n = read(client_fd, buf, sizeof(buf));
            if (n <= 0) { reason = RELAY_DOWNSTREAM; break; }
            clock_gettime(CLOCK_MONOTONIC, &last_downstream);
            if (write(upstream_fd, buf, (size_t)n) != n) {
                reason = RELAY_UPSTREAM; break;
            }
        }
        /* upstream → downstream */
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
static relay_closed_t relay_plain_tls(int client_fd, SSL *upstream_ssl)
{
    uint8_t buf[BUF_SIZE];
    int upstream_fd = SSL_get_fd(upstream_ssl);
    int maxfd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;
    relay_closed_t reason = RELAY_DOWNSTREAM;

    struct timespec last_downstream;
    clock_gettime(CLOCK_MONOTONIC, &last_downstream);

    while (running) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - last_downstream.tv_sec) +
                         (now.tv_nsec - last_downstream.tv_nsec) / 1e9;
        if (elapsed >= 1.0) {
            if (Debug) {
                fprintf(stderr, "%s: downstream timeout (1s)\n", log_prefix);
            }
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd,   &rfds);
        FD_SET(upstream_fd, &rfds);

        double remaining = 1.0 - elapsed;
        if (remaining < 0.0) remaining = 0.0;
        struct timeval tv;
        tv.tv_sec = (time_t)remaining;
        tv.tv_usec = (suseconds_t)((remaining - tv.tv_sec) * 1000000);

        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        /* plain client → TLS upstream */
        if (rc > 0 && FD_ISSET(client_fd, &rfds)) {
            ssize_t n = read(client_fd, buf, sizeof(buf));
            if (n <= 0) { reason = RELAY_DOWNSTREAM; break; }
            clock_gettime(CLOCK_MONOTONIC, &last_downstream);
            if (SSL_write(upstream_ssl, buf, (int)n) <= 0) {
                ERR_print_errors_fp(stderr);
                reason = RELAY_UPSTREAM; break;
            }
        }

        /* TLS upstream → plain client */
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
static relay_closed_t relay_tls_plain(SSL *client_ssl, int upstream_fd)
{
    uint8_t buf[BUF_SIZE];
    int client_fd = SSL_get_fd(client_ssl);
    int maxfd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;
    relay_closed_t reason = RELAY_DOWNSTREAM;

    struct timespec last_downstream;
    clock_gettime(CLOCK_MONOTONIC, &last_downstream);

    while (running) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - last_downstream.tv_sec) +
                         (now.tv_nsec - last_downstream.tv_nsec) / 1e9;
        if (elapsed >= 1.0) {
            if (Debug) {
                fprintf(stderr, "%s: downstream timeout (1s)\n", log_prefix);
            }
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd,   &rfds);
        FD_SET(upstream_fd, &rfds);

        double remaining = 1.0 - elapsed;
        if (remaining < 0.0) remaining = 0.0;
        struct timeval tv;
        tv.tv_sec = (time_t)remaining;
        tv.tv_usec = (suseconds_t)((remaining - tv.tv_sec) * 1000000);

        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        /* TLS client → plain upstream */
        if (rc > 0 && FD_ISSET(client_fd, &rfds)) {
            int n = SSL_read(client_ssl, buf, sizeof(buf));
            if (n <= 0) {
                int err = SSL_get_error(client_ssl, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                    ERR_print_errors_fp(stderr);
                reason = RELAY_DOWNSTREAM; break;
            }
            clock_gettime(CLOCK_MONOTONIC, &last_downstream);
            if (write(upstream_fd, buf, (size_t)n) != n) {
                reason = RELAY_UPSTREAM; break;
            }
        }

        /* plain upstream → TLS client */
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
static relay_closed_t relay_tls_tls(SSL *client_ssl, SSL *upstream_ssl)
{
    uint8_t buf[BUF_SIZE];
    int client_fd   = SSL_get_fd(client_ssl);
    int upstream_fd = SSL_get_fd(upstream_ssl);
    int maxfd = (client_fd > upstream_fd ? client_fd : upstream_fd) + 1;
    relay_closed_t reason = RELAY_DOWNSTREAM;

    struct timespec last_downstream;
    clock_gettime(CLOCK_MONOTONIC, &last_downstream);

    while (running) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - last_downstream.tv_sec) +
                         (now.tv_nsec - last_downstream.tv_nsec) / 1e9;
        if (elapsed >= 1.0) {
            if (Debug) {
                fprintf(stderr, "%s: downstream timeout (1s)\n", log_prefix);
            }
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd,   &rfds);
        FD_SET(upstream_fd, &rfds);

        double remaining = 1.0 - elapsed;
        if (remaining < 0.0) remaining = 0.0;
        struct timeval tv;
        tv.tv_sec = (time_t)remaining;
        tv.tv_usec = (suseconds_t)((remaining - tv.tv_sec) * 1000000);

        int rc = select(maxfd, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        /* TLS client → TLS upstream */
        if (rc > 0 && FD_ISSET(client_fd, &rfds)) {
            int n = SSL_read(client_ssl, buf, sizeof(buf));
            if (n <= 0) {
                int err = SSL_get_error(client_ssl, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_ZERO_RETURN)
                    ERR_print_errors_fp(stderr);
                reason = RELAY_DOWNSTREAM; break;
            }
            clock_gettime(CLOCK_MONOTONIC, &last_downstream);
            if (SSL_write(upstream_ssl, buf, n) <= 0) {
                ERR_print_errors_fp(stderr);
                reason = RELAY_UPSTREAM; break;
            }
        }

        /* TLS upstream → TLS client */
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
/* Per-connection handler (runs in a child process)                    */
/* ------------------------------------------------------------------ */

static void handle_connection(const proxy_cfg_t *cfg, SSL_CTX *server_ctx,
                              int client_fd, uint16_t remote_port,
                              const char *peer_str, uint16_t peer_port)
{
    SSL *client_ssl = NULL;
    if (cfg->use_tls_local) {
        client_ssl = tls_accept(client_fd, server_ctx);
        if (!client_ssl) {
            fprintf(stderr, "%s: local TLS handshake failed with %s:%u\n",
                    log_prefix, peer_str, peer_port);
            close(client_fd);
            return;
        }
        fprintf(stderr, "%s: local TLS handshake ok (%s) with %s:%u\n",
                log_prefix, SSL_get_cipher(client_ssl), peer_str, peer_port);
    }

    /* Upstream connection is opened now, for this client only */
    fprintf(stderr, "%s: connecting to %s:%u%s ...\n", log_prefix,
            cfg->remote_ip, remote_port, cfg->use_tls_remote ? " (TLS)" : "");
    int upstream_fd = connect_to_remote(cfg->remote_ip, remote_port);
    if (upstream_fd < 0) {
        fprintf(stderr, "%s: upstream connect failed\n", log_prefix);
        close(client_fd);
        return;
    }
    SSL *upstream_ssl = NULL;
    if (cfg->use_tls_remote) {
        upstream_ssl = tls_connect(upstream_fd, cfg->remote_ip);
        if (!upstream_ssl) {
            fprintf(stderr, "%s: remote TLS handshake failed\n", log_prefix);
            close(upstream_fd);
            close(client_fd);
            return;
        }
        fprintf(stderr, "%s: remote TLS established (%s)\n",
                log_prefix, SSL_get_cipher(upstream_ssl));
    }

    relay_closed_t closed;
    if (!client_ssl && !upstream_ssl)
        closed = relay_plain_plain(client_fd, upstream_fd);
    else if (!client_ssl && upstream_ssl)
        closed = relay_plain_tls(client_fd, upstream_ssl);
    else if (client_ssl && !upstream_ssl)
        closed = relay_tls_plain(client_ssl, upstream_fd);
    else
        closed = relay_tls_tls(client_ssl, upstream_ssl);

    if (Debug) {
        fprintf(stderr, "%s: connection from %s:%u closed (%s)\n",
                log_prefix, peer_str, peer_port,
                closed == RELAY_UPSTREAM ? "upstream closed" : "downstream closed");
    }

    if (client_ssl)   SSL_free(client_ssl);
    if (upstream_ssl) SSL_free(upstream_ssl);
    close(client_fd);
    close(upstream_fd);
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

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Children are reaped automatically */
    struct sigaction sc;
    memset(&sc, 0, sizeof(sc));
    sc.sa_handler = SIG_DFL;
    sc.sa_flags   = SA_NOCLDWAIT;
    sigemptyset(&sc.sa_mask);
    sigaction(SIGCHLD, &sc, NULL);

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

    /* Open one listening socket per port */
    struct pollfd *pfds = calloc(cfg.num_ports, sizeof(*pfds));
    if (!pfds) { perror("calloc"); return EXIT_FAILURE; }

    for (unsigned i = 0; i < cfg.num_ports; i++) {
        int fd = listen_on((uint16_t)(cfg.local_port + i));
        if (fd < 0) {
            fprintf(stderr, "%s: cannot listen on port %u\n",
                    log_prefix, cfg.local_port + i);
            for (unsigned j = 0; j < i; j++) close(pfds[j].fd);
            free(pfds);
            if (server_ctx) SSL_CTX_free(server_ctx);
            return EXIT_FAILURE;
        }
        pfds[i].fd     = fd;
        pfds[i].events = POLLIN;
    }

    fprintf(stderr, "%s: listening on 0.0.0.0:%u-%u%s -> %s:%u-%u%s\n",
            log_prefix, cfg.local_port, cfg.local_port + cfg.num_ports - 1,
            cfg.use_tls_local ? " (TLS)" : "",
            cfg.remote_ip, cfg.remote_port, cfg.remote_port + cfg.num_ports - 1,
            cfg.use_tls_remote ? " (TLS)" : "");

    while (running) {
        int rc = poll(pfds, cfg.num_ports, 1000);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("poll"); break;
        }
        if (rc == 0) continue;

        for (unsigned i = 0; i < cfg.num_ports; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;

            struct sockaddr_storage peer_sa;
            socklen_t peer_len = sizeof(peer_sa);
            int client_fd = accept(pfds[i].fd, (struct sockaddr *)&peer_sa, &peer_len);
            if (client_fd < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED)
                    continue;
                perror("accept");
                continue;
            }

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

            uint16_t lport = (uint16_t)(cfg.local_port + i);
            uint16_t rport = (uint16_t)(cfg.remote_port + i);
            if (Debug) {
                fprintf(stderr, "%s: accepted connection from %s:%u on port %u -> remote port %u\n",
                        log_prefix, peer_str, peer_port, lport, rport);
            }

            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                close(client_fd);
                continue;
            }
            if (pid == 0) {
                /* Child: serve this single connection */
                for (unsigned j = 0; j < cfg.num_ports; j++) close(pfds[j].fd);
                signal(SIGINT,  SIG_DFL);
                handle_connection(&cfg, server_ctx, client_fd, rport,
                                  peer_str, peer_port);
                _exit(EXIT_SUCCESS);
            }
            close(client_fd);   /* Parent: child owns the connection */
        }
    }

    for (unsigned i = 0; i < cfg.num_ports; i++) close(pfds[i].fd);
    free(pfds);
    if (server_ctx) SSL_CTX_free(server_ctx);

    fprintf(stderr, "%s: shut down cleanly\n", log_prefix);
    return EXIT_SUCCESS;
}
