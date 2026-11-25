#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <libelf.h>
#include <gelf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MY_EBPF_OBJ "geneve_relay_nat.o"

#define GENEVE_PORT 6081

// Hello protocol between neighbors. Hellos are sent through the overlay (geneve0) from/to
// <overlay ip>:HELLO_PORT, i.e. the eBPF filters route/NAT them like any other overlay packet.
#define HELLO_PORT       6082
#define HELLO_PERIOD_MS  10000   // period of new hellos to the same neighbor
#define HELLO_RETRY_MS    2000   // re-send the same hello if no reply arrives within this time
#define HELLO_MAX_POLL_MS 1000  // upper bound for poll() timeout so g_stop is noticed promptly

#define HELLO_TYPE_HELLO 1
#define HELLO_TYPE_REPLY 2


#define LOG_INFO  1
#define LOG_ERROR 2

#define LOG_LEVEL LOG_ERROR

#define log(level, fmt, args...) if (level >= LOG_LEVEL) printf("[%08x] " fmt,  g_local_id_hash, ##args)



// next-hop underlay IP and outer UDP dest port.
// Used as value type in the hash2nh ebpf map (to handle NAT/conntrack)
typedef struct nh_port {
    __be32 nh;
    __be16 port;
 } nh_port;

/* ── Signal handling ─────────────────────────────────────────────────────── */
static volatile sig_atomic_t g_stop = 0;

static struct bpf_tc_hook g_gen_ingress_hook;
static struct bpf_tc_opts g_gen_ingress_opts;
static struct bpf_tc_hook g_gen_egress_hook;
static struct bpf_tc_opts g_gen_egress_opts;

static struct bpf_tc_hook g_udp_ingress_hook;
static struct bpf_tc_opts g_udp_ingress_opts;
static struct bpf_tc_hook g_udp_egress_hook;
static struct bpf_tc_opts g_udp_egress_opts;

static struct bpf_object  *g_obj = NULL;

static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static int get_symbol_offset(const char *elf_path, const char *sym_name, size_t *offset_out) {
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library initialization failed\n");
        close(fd);
        return -1;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "elf_begin failed: %s\n", elf_errmsg(-1));
        close(fd);
        return -1;
    }

    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    Elf_Data *data = NULL;
    int ret = -1;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);
        if (shdr.sh_type == SHT_SYMTAB) {
            data = elf_getdata(scn, NULL);
            int count = shdr.sh_size / shdr.sh_entsize;
            for (int i = 0; i < count; i++) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (name && strcmp(name, sym_name) == 0) {
                    *offset_out = sym.st_value;
                    ret = 0;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    elf_end(elf);
    close(fd);
    return ret;
}

union ip4 {
    uint32_t num;
    unsigned char octets[4];
};

// ebpf maps
static int ip2hash_fd, hash2ip_fd, hash2ind_fd, ind2hash_fd, hash2nh_fd;

/* ── Remote proxies / hello state ────────────────────────────────────────── */
#define MAX_REMOTES 255

typedef struct remote {
    uint32_t hash;          // remote ID hash
    uint32_t overlay_ip;    // local overlay IP of the remote (network byte order)
    bool     neighbor;      // remote is a neighbor (cmd line arg)
    bool     send_hello;    // neighbor with a known (not 0.0.0.0) static nh address
    uint32_t counter;       // counter of the last new hello sent (0 = none yet)
    bool     awaiting;      // hello sent, reply not received yet
    int64_t  next_due_ms;   // when to send the next new hello
    int64_t  last_new_ms;   // when the last new hello was sent
    int64_t  retry_due_ms;  // when to re-send the outstanding hello
} remote;

static remote g_remotes[MAX_REMOTES];
static int g_num_remotes = 0;

// Hello message. All fields are in network byte order.
typedef struct hello_msg {
    uint32_t type;          // HELLO_TYPE_HELLO or HELLO_TYPE_REPLY
    uint32_t sender_id;     // ID hash of the sender (local_id_hash)
    uint32_t counter;       // hello counter. Echoed back unchanged in the reply
} hello_msg;

static int g_hello_sock = -1;
static uint32_t g_local_id_hash;



static int ip4_ptole(const char *p, union ip4 *r) {
    int n = sscanf(p, "%hhu.%hhu.%hhu.%hhu", r->octets + 3, r->octets + 2, r->octets + 1, r->octets);
    if (n != 4) {
        fprintf(stderr, "(E) ip4_ptole() %s n %d", p, n);
        return -1;
    }
    return 0;
}

static int ip4_ptobe(const char *p, union ip4 *r) {
    struct in_addr addr;
    int ret = inet_pton(AF_INET, p, &addr);
    if (ret <= 0) {
        fprintf(stderr, "(E) ip4_ptobe() %s ret %d", p, ret);
        return -1;
    }
    r->num = addr.s_addr;
    return 0;
}

static int new_id_hash_to_maps(uint32_t hash, const char *ip_str, const char *nh_str, bool neighbor) {
    union ip4 ip;
    static uint32_t index = 1;

    if (ip4_ptobe(ip_str, &ip) < 0) {
        fprintf(stderr, "[-] Invalid IP: %s for hash %d\n", ip_str, hash);
        return -1;
    }
    // ip2hash and hash2ip
    if (bpf_map_update_elem(ip2hash_fd, &ip.num, &hash, BPF_ANY) != 0) {
        perror("[-] ip2hash bpf_map_update_elem");
        return -1;
    }

    //if (ip4_ptole(ip_str, &ip) < 0) {
    //    fprintf(stderr, "[-] Invalid IP: %s for hash %d\n", ip_str, hash);
    //    return -1;
    //}
    if (bpf_map_update_elem(hash2ip_fd, &hash, &ip.num, BPF_ANY) != 0) {
        perror("[-] hash2ip bpf_map_update_elem");
        return -1;
    }

    if (index > 255) {
        printf("(E) Max num of hashes exceeded");
        return -1;
    }

    // hash2ind and ind2hash
    if (bpf_map_update_elem(hash2ind_fd, &hash, &index, BPF_ANY) != 0) {
        perror("[-] hash2ind bpf_map_update_elem");
        return -1;
    }
    if (bpf_map_update_elem(ind2hash_fd, &index, &hash, BPF_ANY) != 0) {
        perror("[-] ind2hash bpf_map_update_elem");
        return -1;
    }

    // hash2nh 
    // NOTE nh must be in host order (le) because the set_tunnel_key() call converts it to network order
    union ip4 nh;
    bool nh_known = strcmp(nh_str, "0.0.0.0") != 0;
    if (nh_known) {
        if (ip4_ptole(nh_str, &nh) < 0) {
            fprintf(stderr, "[-] Invalid nh IP: %s for hash %d\n", nh_str, hash);
            return -1;
        }
        nh_port nhp = { nh.num, htons(GENEVE_PORT) };
        if (bpf_map_update_elem(hash2nh_fd, &hash, &nhp, BPF_ANY) != 0) {
            perror("[-] hash2nh bpf_map_update_elem");
            return -1;
        }
    } else {
        // peer site is private, nh is not known yet
        nh.num = 0;
    }

    // Remember the remote for the hello protocol. Only neighbors with a known static nh are probed.
    if (g_num_remotes >= MAX_REMOTES) {
        fprintf(stderr, "[-] Too many remote proxies\n");
        return -1;
    }
    remote *r = &g_remotes[g_num_remotes++];
    r->hash = hash;
    r->overlay_ip = ip.num;
    r->neighbor = neighbor;
    r->send_hello = neighbor && nh_known;

    printf("[+] IP <-> hash: hash %-5d  ind %d neighbor %d "
            "ip %-15s 0x%-8x ip[0] %02x ip[1] %02x ip[2] %02x ip[3] %02x "
            "nh %-15s 0x%-8x nh[0] %02x nh[1] %02x nh[2] %02x nh[3] %02x\n",
            hash, index, neighbor,
            ip_str, ip.num, ip.octets[0],  ip.octets[1],  ip.octets[2],  ip.octets[3],
            nh_str, nh.num, nh.octets[0],  nh.octets[1],  nh.octets[2],  nh.octets[3]);
    index += 1;

    return 0;
}

/* Attach a BPF program to TC ingress or egress at a given pref.
 * Returns the handle assigned by the kernel (needed for detach), or -1. */
static int tc_attach_bpf(unsigned int ifindex, int attach_point,
                         int prog_fd, uint32_t pref,
                         struct bpf_tc_hook *hook_out,
                         struct bpf_tc_opts *opts_out)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .sz          = sizeof(struct bpf_tc_hook),
        .ifindex     = ifindex,
        .attach_point = attach_point,
    );
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .sz      = sizeof(struct bpf_tc_opts),
        .prog_fd = prog_fd,
        .priority = pref,
    );

    if (attach_point == BPF_TC_INGRESS)
        bpf_tc_hook_create(&hook);   /* idempotent — ok if clsact already exists */

    if (bpf_tc_attach(&hook, &opts) < 0) {
        perror("[-] bpf_tc_attach");
        return -1;
    }
    *hook_out = hook;
    *opts_out = opts;
    // bpf_tc_detach() rejects (-EINVAL) opts with prog_fd, prog_id or flags set. Only handle
    // and priority (filled in by bpf_tc_attach()) may be non-zero.
    opts_out->prog_fd = 0;
    opts_out->prog_id = 0;
    opts_out->flags   = 0;
    return 0;
}

int set_global_ebpf_vars(struct bpf_object *obj, uint32_t local_id_hash, const char *local_overlay_ip) {
    /* Set global variable LOCAL_ID_HASH in .rodata before loading */
    struct bpf_map *rodata_map = NULL;
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        if (strstr(name, ".rodata")) {
            rodata_map = map;
            break;
        }
    }

    if (!rodata_map) {
        fprintf(stderr, "[-] .rodata map not found in eBPF object. Make sure LOCAL_ID_HASH is defined.\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    size_t rodata_sz;
    void *rodata_data = bpf_map__initial_value(rodata_map, &rodata_sz);
    if (!rodata_data) {
        fprintf(stderr, "[-] bpf_map__initial_value failed to get .rodata map pointer\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    // set LOCAL_ID_HASH
    size_t key_offset = 0;
    if (get_symbol_offset(MY_EBPF_OBJ, "LOCAL_ID_HASH", &key_offset) < 0) {
        fprintf(stderr, "[-] Failed to find offset of LOCAL_ID_HASH in ELF symbol table\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    if (key_offset + sizeof(uint32_t) > rodata_sz) {
        fprintf(stderr, "[-] LOCAL_ID_HASH offset (%zu) out of .rodata boundaries (%zu bytes)\n", key_offset, rodata_sz);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    *(uint32_t *)((char *)rodata_data + key_offset) = local_id_hash;
    printf("[+] Setting LOCAL_ID_HASH to %u in .rodata (offset: %zu)\n", local_id_hash, key_offset);

    // set LOCAL_OVERLAY_IP
    key_offset = 0;
    if (get_symbol_offset(MY_EBPF_OBJ, "LOCAL_OVERLAY_IP", &key_offset) < 0) {
        fprintf(stderr, "[-] Failed to find offset of LOCAL_OVERLAY_IP in ELF symbol table\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    if (key_offset + sizeof(uint32_t) > rodata_sz) {
        fprintf(stderr, "[-] LOCAL_OVERLAY_IP offset (%zu) out of .rodata boundaries (%zu bytes)\n", key_offset, rodata_sz);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    union ip4 ip;
    if (ip4_ptobe(local_overlay_ip, &ip) < 0) {
        fprintf(stderr, "[-] Invalid local overlay IP: %s\n", local_overlay_ip);
        return -1;
    }
    *(uint32_t *)((char *)rodata_data + key_offset) = ip.num;
    printf("[+] Setting LOCAL_OVERLAY_IP to %s %08x in .rodata (offset: %zu)\n", local_overlay_ip, ip.num, key_offset);

    return 0;
} 

int init_ebpf_maps(struct bpf_object *obj, uint32_t num_remote_proxies, char **argv) {
    // ip2hash
    struct bpf_map *routes_map = bpf_object__find_map_by_name(obj, "ip2hash");
    ip2hash_fd = bpf_map__fd(routes_map);
    if (ip2hash_fd < 0) {
        fprintf(stderr, "[-] map 'ip2hash' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    // hash2ip
    routes_map = bpf_object__find_map_by_name(obj, "hash2ip");
    hash2ip_fd = bpf_map__fd(routes_map);
    if (hash2ip_fd < 0) {
        fprintf(stderr, "[-] map 'hash2ip' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    // hash2ind
    routes_map = bpf_object__find_map_by_name(obj, "hash2ind");
    hash2ind_fd = bpf_map__fd(routes_map);
    if (hash2ind_fd < 0) {
        fprintf(stderr, "[-] map 'hash2ind' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    // ind2hash
    routes_map = bpf_object__find_map_by_name(obj, "ind2hash");
    ind2hash_fd = bpf_map__fd(routes_map);
    if (ind2hash_fd < 0) {
        fprintf(stderr, "[-] map 'ind2hash' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    // hash2nh
    routes_map = bpf_object__find_map_by_name(obj, "hash2nh");
    hash2nh_fd = bpf_map__fd(routes_map);
    if (hash2nh_fd < 0) {
        fprintf(stderr, "[-] map 'hash2nh' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    int arg_offset = 6;
    for(int i = 0; i < num_remote_proxies; i++) {
        uint32_t hash = (uint32_t)strtoul(argv[arg_offset], NULL, 10);
        const char *ip_str = argv[arg_offset + 1];
        const char *nh_str = argv[arg_offset + 2];
        const char *nbr_str = argv[arg_offset + 3];
        if (strcmp(nbr_str, "0") && strcmp(nbr_str, "1")) {
            fprintf(stderr, "[-] Invalid is_neighbor value '%s' for hash %u (must be 0 or 1)\n", nbr_str, hash);
            return -1;
        }
        int ret = new_id_hash_to_maps(hash, ip_str, nh_str, nbr_str[0] == '1');
        if (ret != 0) {
            return ret;
        }
        arg_offset += 4;
    }
    return 0;
}

/* ── Hello protocol ──────────────────────────────────────────────────────── */

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static remote *find_remote(uint32_t hash) {
    for (int i = 0; i < g_num_remotes; i++) {
        if (g_remotes[i].hash == hash)
            return &g_remotes[i];
    }
    return NULL;
}

static void hello_send(const struct sockaddr_in *to, uint32_t type, uint32_t sender_id, uint32_t counter) {
    hello_msg msg = { htonl(type), htonl(sender_id), htonl(counter) };
    if (sendto(g_hello_sock, &msg, sizeof(msg), 0, (const struct sockaddr *)to, sizeof(*to)) < 0)
        perror("[-] hello sendto");
}

static void hello_send_to_remote(const remote *r, uint32_t counter) {
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons(HELLO_PORT) };
    to.sin_addr.s_addr = r->overlay_ip;
    hello_send(&to, HELLO_TYPE_HELLO, g_local_id_hash, counter);
}

// Create the UDP socket used to both send and receive hello messages. It is bound to
// <local overlay ip>:HELLO_PORT (the eBPF UDP filters require the inner source IP to be
// LOCAL_OVERLAY_IP).
static int hello_init(uint32_t local_id_hash, const char *local_overlay_ip) {
    union ip4 ip;
    if (ip4_ptobe(local_overlay_ip, &ip) < 0)
        return -1;

    g_local_id_hash = local_id_hash;
    g_hello_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_hello_sock < 0) {
        perror("[-] hello socket");
        return -1;
    }
    int one = 1;
    setsockopt(g_hello_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(HELLO_PORT) };
    addr.sin_addr.s_addr = ip.num;
    if (bind(g_hello_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[-] hello bind");
        close(g_hello_sock);
        g_hello_sock = -1;
        return -1;
    }

    int64_t now = now_ms();
    for (int i = 0; i < g_num_remotes; i++)
        g_remotes[i].next_due_ms = now; // first hello goes out immediately
    printf("[+] Hello socket bound to %s:%d\n", local_overlay_ip, HELLO_PORT);
    return 0;
}

static void hello_receive(void) {
    for (;;) {
        hello_msg msg;
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(g_hello_sock, &msg, sizeof(msg), MSG_DONTWAIT,
                             (struct sockaddr *)&from, &fromlen);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                perror("[-] hello recvfrom");
            return;
        }
        if (n != sizeof(msg))
            continue;

        uint32_t type = ntohl(msg.type);
        uint32_t sender = ntohl(msg.sender_id);
        uint32_t counter = ntohl(msg.counter);

        if (type == HELLO_TYPE_HELLO) {
            log(LOG_INFO, "[hello] received hello from id %u counter %u, sending reply\n", sender, counter);
            hello_send(&from, HELLO_TYPE_REPLY, g_local_id_hash, counter);
        } else if (type == HELLO_TYPE_REPLY) {
            remote *r = find_remote(sender);
            if (!r || !r->send_hello || !r->awaiting || r->counter != counter) {
                log(LOG_INFO, "[hello] ignoring reply from id %u counter %u\n", sender, counter);
                continue;
            }
            int64_t now = now_ms();
            log(LOG_INFO, "[hello] reply from id %u counter %u rtt %lld ms\n", sender, counter,
                   (long long)(now - r->last_new_ms));
            r->awaiting = false;
            r->next_due_ms = r->last_new_ms + HELLO_PERIOD_MS;
        }
    }
}

// One iteration of the hello loop: wait for incoming hello/reply messages or the next
// timer, handle received messages, send new hellos and re-send unanswered ones.
static void hello_neighbor(void) {
    int64_t now = now_ms();
    int64_t wake = now + HELLO_MAX_POLL_MS;
    for (int i = 0; i < g_num_remotes; i++) {
        const remote *r = &g_remotes[i];
        if (!r->send_hello)
            continue;
        int64_t due = r->awaiting ? r->retry_due_ms : r->next_due_ms;
        if (due < wake)
            wake = due;
    }
    int timeout = wake > now ? (int)(wake - now) : 0;

    struct pollfd pfd = { .fd = g_hello_sock, .events = POLLIN };
    int ret = poll(&pfd, 1, timeout);
    if (ret < 0) {
        if (errno != EINTR)
            perror("[-] hello poll");
        return;
    }
    if (ret > 0 && (pfd.revents & POLLIN))
        hello_receive();

    now = now_ms();
    for (int i = 0; i < g_num_remotes; i++) {
        remote *r = &g_remotes[i];
        if (!r->send_hello)
            continue;
        if (!r->awaiting && now >= r->next_due_ms) {
            r->counter++;
            r->awaiting = true;
            r->last_new_ms = now;
            r->retry_due_ms = now + HELLO_RETRY_MS;
            log(LOG_INFO, "[hello] sending hello to id %u counter %u\n", r->hash, r->counter);
            hello_send_to_remote(r, r->counter);
        } else if (r->awaiting && now >= r->retry_due_ms) {
            r->retry_due_ms = now + HELLO_RETRY_MS;
            log(LOG_INFO, "[hello] no reply from id %u, re-sending hello counter %u\n", r->hash, r->counter);
            hello_send_to_remote(r, r->counter);
        }
    }
}

void usage(char *argv0) {
    fprintf(stderr, "Usage: %s <geneve_iface> <udp_iface|none> <local_id_hash> <local_overlay_ip> <num_remote_proxies [1..255]>\n"
                "<remote_id_hash> <remote_overlay_ip> <nh_underlay_ip> <is_neighbor 0|1> ...\n", argv0);
}

int main(int argc, char **argv)
{
    if (argc < 6) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *geneve_iface = argv[1];
    unsigned int geneve_ifindex = if_nametoindex(geneve_iface);
    if (geneve_ifindex == 0) {
        perror("[-] if_nametoindex for geneve iface");
        return EXIT_FAILURE;
    }

    const char *udp_iface = argv[2];
    if (!strcmp(udp_iface, "none")) {
        udp_iface = NULL; // udp_iface is optional
    }
    unsigned int udp_ifindex = 0;
    if (udp_iface) {
        udp_ifindex = if_nametoindex(udp_iface);
        if (udp_ifindex == 0) {
            perror("[-] if_nametoindex for udp iface");
            return EXIT_FAILURE;
        }
    }

    uint32_t local_id_hash = (uint32_t)strtoul(argv[3], NULL, 10);
    const char *local_overlay_ip = argv[4];
    uint32_t num_remote_proxies = (uint32_t)strtoul(argv[5], NULL, 10);
    if (num_remote_proxies < 1 || num_remote_proxies > 255) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (argc < 6 + (int)(4 * num_remote_proxies)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Open the ebpf object
    struct bpf_object *obj = bpf_object__open_file(MY_EBPF_OBJ, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[-] bpf_object__open_file\n");
        return EXIT_FAILURE;
    }

    // set global ebpf vars
    int ret = set_global_ebpf_vars(obj, local_id_hash, local_overlay_ip);
    if (ret) {
        return ret;
    }

    // load ebpf object
    if (bpf_object__load(obj)) {
        fprintf(stderr, "[-] bpf_object__load\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    // Populate ebpf maps with values from argv
    ret = init_ebpf_maps(obj, num_remote_proxies, argv);
    if (ret)
        return EXIT_FAILURE;

    // Create the hello socket (needs the remotes parsed by init_ebpf_maps())
    if (hello_init(local_id_hash, local_overlay_ip) < 0) {
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* ── 3. Find programs by name ────────────────────────────────────────── */
    struct bpf_program *geneve_ingress_prog =
        bpf_object__find_program_by_name(obj, "geneve_ingress_redirect");
    struct bpf_program *geneve_egress_prog =
        bpf_object__find_program_by_name(obj, "geneve_egress_rewrite");
    struct bpf_program *udp_ingress_prog =
        bpf_object__find_program_by_name(obj, "udp_port_save");
    struct bpf_program *udp_egress_prog =
        bpf_object__find_program_by_name(obj, "udp_port_rewrite");

        if (!geneve_ingress_prog || !geneve_egress_prog || !udp_ingress_prog || !udp_egress_prog) {
        fprintf(stderr, "[-] eBPF program(s) not found in object\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* ── 4. Register SIGINT handler ─────────────────────────────────────── */
    struct sigaction sa = {};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL); // tunnel-relay-3-vm.sh stops us with "kill" (SIGTERM)

    /* ── 5. Attach ingress eBPF ──────────────────────────────────────────── */
    g_obj = obj;
    if (tc_attach_bpf(geneve_ifindex, BPF_TC_INGRESS,
                      bpf_program__fd(geneve_ingress_prog), 1,
                      &g_gen_ingress_hook, &g_gen_ingress_opts) < 0) {
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] Ingress eBPF attached (pref 1) on %s\n", geneve_iface);

    /* ── 6. Attach egress eBPF at pref 1 ─────────────────────────────────── */
    if (tc_attach_bpf(geneve_ifindex, BPF_TC_EGRESS,
                      bpf_program__fd(geneve_egress_prog), 1,
                      &g_gen_egress_hook, &g_gen_egress_opts) < 0) {
        bpf_tc_detach(&g_gen_ingress_hook, &g_gen_ingress_opts);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] Egress  eBPF attached (pref 1) on %s\n", geneve_iface);

    if (udp_iface) {
        if (tc_attach_bpf(udp_ifindex, BPF_TC_INGRESS,
                      bpf_program__fd(udp_ingress_prog), 1,
                      &g_udp_ingress_hook, &g_udp_ingress_opts) < 0) {
            bpf_tc_detach(&g_gen_ingress_hook, &g_gen_ingress_opts);
            bpf_tc_detach(&g_gen_egress_hook, &g_gen_egress_opts);
            bpf_object__close(obj);
            return EXIT_FAILURE;
        }
        printf("[+] Ingress eBPF attached (pref 1) on %s\n", udp_iface);
        if (tc_attach_bpf(udp_ifindex, BPF_TC_EGRESS,
                      bpf_program__fd(udp_egress_prog), 1,
                      &g_udp_egress_hook, &g_udp_egress_opts) < 0) {
            bpf_tc_detach(&g_gen_ingress_hook, &g_gen_ingress_opts);
            bpf_tc_detach(&g_gen_egress_hook, &g_gen_egress_opts);
            bpf_tc_detach(&g_udp_ingress_hook, &g_udp_ingress_opts);
            bpf_object__close(obj);
            return EXIT_FAILURE;
        }
        printf("[+] Egress  eBPF attached (pref 1) on %s\n", udp_iface);
    }
    //printf("\nRunning — press Ctrl-C to detach and stop...\n");
    while (!g_stop)
        hello_neighbor();

    /* ── 7. Cleanup ──────────────────────────────────────────────────────── */
    printf("\n[*] Caught SIGINT, cleaning up...\n");
    bpf_tc_detach(&g_gen_egress_hook,  &g_gen_egress_opts);
    bpf_tc_detach(&g_gen_ingress_hook, &g_gen_ingress_opts);
    bpf_tc_detach(&g_udp_ingress_hook, &g_udp_ingress_opts);
    bpf_tc_detach(&g_udp_egress_hook, &g_udp_egress_opts);
    close(g_hello_sock);
    bpf_object__close(obj);
    return EXIT_SUCCESS;
}
