#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <libelf.h>
#include <gelf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MY_EBPF_OBJ "geneve_relay.o"

/* ── Signal handling ─────────────────────────────────────────────────────── */
static volatile sig_atomic_t g_stop = 0;

static struct bpf_tc_hook g_ingress_hook;
static struct bpf_tc_opts g_ingress_opts;
static struct bpf_tc_hook g_egress_hook;
static struct bpf_tc_opts g_egress_opts;
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

static int new_id_hash_to_maps(uint32_t hash, const char *ip_str, const char *nh_str) {
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
    union ip4 nh;
    if (ip4_ptole(nh_str, &nh) < 0) {
        fprintf(stderr, "[-] Invalid nh IP: %s for hash %d\n", nh_str, hash);
        return -1;
    }
    if (bpf_map_update_elem(hash2nh_fd, &hash, &nh.num, BPF_ANY) != 0) {
        perror("[-] hash2nh bpf_map_update_elem");
        return -1;
    }

    printf("[+] IP <-> hash: hash %-5d  ind %d "
            "ip %-15s 0x%-8x ip[0] %02x ip[1] %02x ip[2] %02x ip[3] %02x "
            "nh %-15s 0x%-8x nh[0] %02x nh[1] %02x nh[2] %02x nh[3] %02x\n",
            hash, index,
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
    if (hash2ind_fd < 0) {
        fprintf(stderr, "[-] map 'hash2nh' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    int arg_offset = 5;
    for(int i = 0; i < num_remote_proxies; i++) {
        uint32_t hash = (uint32_t)strtoul(argv[arg_offset], NULL, 10);
        const char *ip_str = argv[arg_offset + 1];
        const char *nh_str = argv[arg_offset + 2];
        int ret = new_id_hash_to_maps(hash, ip_str, nh_str);
        if (ret != 0) {
            return ret;
        }
        arg_offset += 3;
    }
    return 0;
}

void usage(char *argv0) {
    fprintf(stderr, "Usage: %s <iface> <local_id_hash> <local_overlay_ip> <num_remote_proxies [1..255]>\n"
                "<remote_id_hash> <remote_overlay_ip> <nh_underlay_ip> ...", argv0);
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("[-] if_nametoindex");
        return EXIT_FAILURE;
    }

    uint32_t local_id_hash = (uint32_t)strtoul(argv[2], NULL, 10);
    const char *local_overlay_ip = argv[3];
    uint32_t num_remote_proxies = (uint32_t)strtoul(argv[4], NULL, 10);
    if (num_remote_proxies < 1 || num_remote_proxies > 255) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (argc < 5 + (int)(3 * num_remote_proxies)) {
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

    /*  opt 100 (0x64) — left→right leg: src=RELAY_RIGHT, dst=RIGHT_UNDERLAY  */
    //update_route(routes_fd, 100, "10.0.1.2", "10.0.1.3");
    /*  opt 200 (0xC8) — right→left leg: src=RELAY_LEFT,  dst=LEFT_UNDERLAY   */
    //update_route(routes_fd, 200, "10.0.0.2", "10.0.0.1");

    /* ── 3. Find programs by name ────────────────────────────────────────── */
    struct bpf_program *ingress_prog =
        bpf_object__find_program_by_name(obj, "geneve_ingress_redirect");
    struct bpf_program *egress_prog =
        bpf_object__find_program_by_name(obj, "geneve_egress_rewrite");
    if (!ingress_prog || !egress_prog) {
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

    /* ── 5. Attach ingress eBPF ──────────────────────────────────────────── */
    g_obj = obj;
    if (tc_attach_bpf(ifindex, BPF_TC_INGRESS,
                      bpf_program__fd(ingress_prog), 1,
                      &g_ingress_hook, &g_ingress_opts) < 0) {
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] Ingress eBPF attached (pref 1) on %s\n", iface);

    /* ── 6. Attach egress eBPF at pref 1 ─────────────────────────────────── */
    if (tc_attach_bpf(ifindex, BPF_TC_EGRESS,
                      bpf_program__fd(egress_prog), 1,
                      &g_egress_hook, &g_egress_opts) < 0) {
        bpf_tc_detach(&g_ingress_hook, &g_ingress_opts);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] Egress  eBPF attached (pref 1) on %s\n", iface);

    //printf("\nRunning — press Ctrl-C to detach and stop...\n");
    while (!g_stop)
        pause();

    /* ── 7. Cleanup ──────────────────────────────────────────────────────── */
    printf("\n[*] Caught SIGINT, cleaning up...\n");
    bpf_tc_detach(&g_egress_hook,  &g_egress_opts);
    bpf_tc_detach(&g_ingress_hook, &g_ingress_opts);
    bpf_object__close(obj);
    return EXIT_SUCCESS;
}
