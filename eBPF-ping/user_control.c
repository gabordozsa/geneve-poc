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

#define MY_EBPF_OBJ "redirect_map.o"

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

/*
 * Must mirror the struct in redirect_map.c exactly.
 * local_ipv4  — new outer source IP for the egress leg
 * remote_ipv4 — new outer destination IP for the egress leg
 */
union ip4 {
    uint32_t num;
    unsigned char octets[4];
};

struct route_entry {
    union ip4 local_ipv4;
    union ip4 remote_ipv4;
};

static int ip4_ptoh(const char *p, union ip4 *r) {
    int n = sscanf(p, "%hhu.%hhu.%hhu.%hhu", r->octets + 3, r->octets + 2, r->octets + 1, r->octets);
    if (n != 4) {
        fprintf(stderr, "(E) ip4_ptoh() %s n %d", p, n);
        return -1;
    }
    return 0;
}

static int update_route(int map_fd, uint32_t option_val,
                        const char *local_ip_str, const char *remote_ip_str)
{
    uint32_t key = option_val;
    struct route_entry value = {};

    if (ip4_ptoh(local_ip_str, &value.local_ipv4) < 0) {
        fprintf(stderr, "[-] Invalid local IP: %s\n", local_ip_str);
        return -1;
    }
    if (ip4_ptoh(remote_ip_str, &value.remote_ipv4) < 0) {
        fprintf(stderr, "[-] Invalid remote IP: %s\n", remote_ip_str);
        return -1;
    }
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
        perror("[-] bpf_map_update_elem");
        return -1;
    }
    printf("[+] Route: opt %-3u  src %-15s 0x%-8x dst %s 0x%-8x\n",
           option_val, local_ip_str, value.local_ipv4.num ,remote_ip_str, value.remote_ipv4.num);
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

    //if (attach_point == BPF_TC_INGRESS)
    bpf_tc_hook_create(&hook);   /* idempotent — ok if clsact already exists */

    if (bpf_tc_attach(&hook, &opts) < 0) {
        perror("[-] bpf_tc_attach");
        return -1;
    }
    *hook_out = hook;
    *opts_out = opts;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <iface> <local_routing_key> (e.g. geneve-in 300)\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("[-] if_nametoindex");
        return EXIT_FAILURE;
    }

    uint32_t local_routing_key = (uint32_t)strtoul(argv[2], NULL, 10);

    /* ── 1. Load eBPF object ─────────────────────────────────────────────── */
    struct bpf_object *obj = bpf_object__open_file(MY_EBPF_OBJ, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[-] bpf_object__open_file\n");
        return EXIT_FAILURE;
    }

    /* Set global variable LOCAL_ROUTING_KEY in .rodata before loading */
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
        fprintf(stderr, "[-] .rodata map not found in eBPF object. Make sure LOCAL_ROUTING_KEY is defined.\n");
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

    size_t key_offset = 0;
    if (get_symbol_offset(MY_EBPF_OBJ, "LOCAL_ROUTING_KEY", &key_offset) < 0) {
        fprintf(stderr, "[-] Failed to find offset of LOCAL_ROUTING_KEY in ELF symbol table\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    if (key_offset + sizeof(uint32_t) > rodata_sz) {
        fprintf(stderr, "[-] LOCAL_ROUTING_KEY offset (%zu) out of .rodata boundaries (%zu bytes)\n", key_offset, rodata_sz);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    // Set LOCAL_ROUTING_KEY at its resolved offset
    *(uint32_t *)((char *)rodata_data + key_offset) = local_routing_key;
    printf("[+] Setting LOCAL_ROUTING_KEY to %u in .rodata (offset: %zu)\n", local_routing_key, key_offset);

    if (bpf_object__load(obj)) {
        fprintf(stderr, "[-] bpf_object__load\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* ── 2. Populate geneve_routes map ───────────────────────────────────── */
    struct bpf_map *routes_map = bpf_object__find_map_by_name(obj, "geneve_routes");
    int routes_fd = bpf_map__fd(routes_map);
    if (routes_fd < 0) {
        fprintf(stderr, "[-] map 'geneve_routes' not found\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /*  opt 100 (0x64) — left→right leg: src=RELAY_RIGHT, dst=RIGHT_UNDERLAY  */
    update_route(routes_fd, 100, "10.0.1.2", "10.0.1.3");
    /*  opt 200 (0xC8) — right→left leg: src=RELAY_LEFT,  dst=LEFT_UNDERLAY   */
    update_route(routes_fd, 200, "10.0.0.2", "10.0.0.1");

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
    /*
     * TC pref (priority) ordering on the egress chain:
     *   pref 1 — geneve_egress_rewrite  (eBPF, returns TC_ACT_PIPE)
     *
     */
    if (tc_attach_bpf(ifindex, BPF_TC_EGRESS,
                      bpf_program__fd(egress_prog), 1,
                      &g_egress_hook, &g_egress_opts) < 0) {
        bpf_tc_detach(&g_ingress_hook, &g_ingress_opts);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] Egress  eBPF attached (pref 1) on %s\n", iface);

    printf("\nRunning — press Ctrl-C to detach and stop...\n");
    while (!g_stop)
        pause();

    /* ── 7. Cleanup ──────────────────────────────────────────────────────── */
    printf("\n[*] Caught SIGINT, cleaning up...\n");
    bpf_tc_detach(&g_egress_hook,  &g_egress_opts);
    bpf_tc_detach(&g_ingress_hook, &g_ingress_opts);
    bpf_object__close(obj);
    return EXIT_SUCCESS;
}
