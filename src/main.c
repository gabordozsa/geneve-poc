/*
 * main.c — Geneve tunnel entry point
 *
 * Responsibilities:
 *   - Parse and validate command-line arguments (getopt)
 *   - Open the TUN device and UDP socket
 *   - Start the bidirectional forwarding loop
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>

#include <arpa/inet.h>
#include <net/if.h>

#include "geneve.h"

/* ------------------------------------------------------------------ */
/* Usage                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *progname)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Required:\n"
        "  -l <addr>   Local IP address to bind (outer transport)\n"
        "  -r <addr>   Remote peer IP address\n"
        "  -v <vni>    Virtual Network Identifier (1–%u)\n"
        "\n"
        "Optional:\n"
        "  -p <port>   UDP port for Geneve (default: %d)\n"
        "  -i <iface>  TUN device name   (default: %s)\n"
        "  -t <type>   Inner protocol: udp | tcp | eth (default: udp)\n"
        "                udp/tcp → EtherType 0x0800 (IP payload)\n"
        "                eth     → EtherType 0x6558 (Ethernet frame)\n"
        "  -m <mtu>    Inner MTU (576–65535, default: %d)\n"
        "  -d          Enable debug logging\n"
        "  -h          Print this help and exit\n",
        progname,
        GENEVE_VNI_MAX,
        GENEVE_PORT_DEFAULT,
        TUN_IFACE_DEFAULT,
        INNER_MTU_DEFAULT);
}

/* ------------------------------------------------------------------ */
/* Argument parsing                                                    */
/* ------------------------------------------------------------------ */

/*
 * parse_args() — populate *cfg from argc/argv.
 *
 * Returns 0 on success, -1 on any validation error.
 * Prints an explanatory message to stderr on error.
 */
static int parse_args(int argc, char *argv[], config_t *cfg)
{
    /* Defaults */
    memset(cfg, 0, sizeof(*cfg));
    cfg->port       = GENEVE_PORT_DEFAULT;
    cfg->proto_type = ETHERTYPE_IPV4;
    cfg->mtu        = INNER_MTU_DEFAULT;
    cfg->debug      = 0;
    strncpy(cfg->tun_iface, TUN_IFACE_DEFAULT, IFNAMSIZ - 1);

    int local_set  = 0;
    int remote_set = 0;
    int vni_set    = 0;

    int opt;
    while ((opt = getopt(argc, argv, "l:r:v:p:i:t:m:dh")) != -1) {
        switch (opt) {

        /* ---- Required arguments ---- */

        case 'l':
            strncpy(cfg->local_addr, optarg, sizeof(cfg->local_addr) - 1);
            local_set = 1;
            break;

        case 'r':
            strncpy(cfg->remote_addr, optarg, sizeof(cfg->remote_addr) - 1);
            remote_set = 1;
            break;

        case 'v': {
            char *end;
            errno = 0;
            unsigned long val = strtoul(optarg, &end, 0);
            if (errno != 0 || *end != '\0' || val == 0 || val > GENEVE_VNI_MAX) {
                fprintf(stderr, "error: vni must be 1–%u\n", GENEVE_VNI_MAX);
                return -1;
            }
            cfg->vni = (uint32_t)val;
            vni_set = 1;
            break;
        }

        /* ---- Optional arguments ---- */

        case 'p': {
            char *end;
            errno = 0;
            unsigned long val = strtoul(optarg, &end, 0);
            if (errno != 0 || *end != '\0' || val == 0 || val > 65535) {
                fprintf(stderr, "error: port must be 1–65535\n");
                return -1;
            }
            cfg->port = (uint16_t)val;
            break;
        }

        case 'i':
            strncpy(cfg->tun_iface, optarg, IFNAMSIZ - 1);
            break;

        case 't':
            if (strcmp(optarg, "udp") == 0 || strcmp(optarg, "tcp") == 0) {
                cfg->proto_type = ETHERTYPE_IPV4;
            } else if (strcmp(optarg, "eth") == 0) {
                cfg->proto_type = ETHERTYPE_ETH_FRAME;
            } else {
                fprintf(stderr,
                        "error: -t must be 'udp', 'tcp', or 'eth'\n");
                return -1;
            }
            break;

        case 'm': {
            char *end;
            errno = 0;
            unsigned long val = strtoul(optarg, &end, 0);
            if (errno != 0 || *end != '\0' || val < 576 || val > 65535) {
                fprintf(stderr, "error: mtu must be 576–65535\n");
                return -1;
            }
            cfg->mtu = (int)val;
            break;
        }

        case 'd':
            cfg->debug = 1;
            break;

        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);

        default:
            usage(argv[0]);
            return -1;
        }
    }

    /* ---- Check required arguments ---- */
    if (!local_set) {
        fprintf(stderr, "error: -l <local_addr> is required\n");
        return -1;
    }
    if (!remote_set) {
        fprintf(stderr, "error: -r <remote_addr> is required\n");
        return -1;
    }
    if (!vni_set) {
        fprintf(stderr, "error: -v <vni> is required\n");
        return -1;
    }

    /* ---- Validate IP addresses (basic AF-agnostic check) ---- */
    union { struct in_addr v4; struct in6_addr v6; } tmp;
    if (inet_pton(AF_INET, cfg->local_addr, &tmp.v4) != 1 &&
        inet_pton(AF_INET6, cfg->local_addr, &tmp.v6) != 1) {
        fprintf(stderr, "error: '%s' is not a valid IP address\n",
                cfg->local_addr);
        return -1;
    }
    if (inet_pton(AF_INET, cfg->remote_addr, &tmp.v4) != 1 &&
        inet_pton(AF_INET6, cfg->remote_addr, &tmp.v6) != 1) {
        fprintf(stderr, "error: '%s' is not a valid IP address\n",
                cfg->remote_addr);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    config_t cfg;

    if (parse_args(argc, argv, &cfg) < 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Register clean-shutdown signal handlers before touching fds */
    setup_signals();

    /* Open TUN device (requires CAP_NET_ADMIN / root) */
    int tun_fd = tun_open(cfg.tun_iface);
    if (tun_fd < 0)
        return EXIT_FAILURE;

    /* Create and bind outer UDP socket */
    int sock_fd = socket_open(&cfg);
    if (sock_fd < 0) {
        close(tun_fd);
        return EXIT_FAILURE;
    }

    /* Print configuration summary */
    fprintf(stderr,
            "geneve: local=%-18s  remote=%-18s  vni=%-8u  port=%u\n"
            "geneve: tun=%-8s  proto=0x%04X  mtu=%d  debug=%s\n",
            cfg.local_addr, cfg.remote_addr, cfg.vni, cfg.port,
            cfg.tun_iface, cfg.proto_type, cfg.mtu,
            cfg.debug ? "on" : "off");

    /* Build tunnel context and enter the event loop */
    tunnel_ctx_t ctx = {
        .tun_fd  = tun_fd,
        .sock_fd = sock_fd,
        .cfg     = &cfg,
    };

    run_tunnel(&ctx);   /* returns only after SIGINT/SIGTERM */

    return EXIT_SUCCESS;
}
