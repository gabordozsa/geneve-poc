#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MY_EBPF_OBJ "udp-port-rewrite.o"

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* Attach a BPF program to TC ingress or egress of the given interface.
 * Returns 0 on success and fills hook_out/opts_out (needed for detach). */
static int tc_attach_bpf(unsigned int ifindex, int attach_point, int prog_fd,
                         struct bpf_tc_hook *hook_out,
                         struct bpf_tc_opts *opts_out)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex      = ifindex,
        .attach_point = attach_point,
    );
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd  = prog_fd,
        .priority = 1,
    );

    /* The clsact qdisc serves both directions, so create it only once.
     * It is fine if it already exists. */
    int err;
    if (attach_point == BPF_TC_INGRESS) {
        err = bpf_tc_hook_create(&hook);
        if (err && err != -EEXIST) {
            fprintf(stderr, "[-] bpf_tc_hook_create: %s\n", strerror(-err));
            return -1;
        }
    }

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "[-] bpf_tc_attach: %s\n", strerror(-err));
        return -1;
    }
    *hook_out = hook;
    *opts_out = opts;
    return 0;
}

/* Detach a filter attached by tc_attach_bpf(). bpf_tc_detach() requires
 * prog_fd, prog_id and flags to be zero; only handle and priority are used. */
static void tc_detach_bpf(struct bpf_tc_hook *hook, struct bpf_tc_opts *opts)
{
    opts->prog_fd = 0;
    opts->prog_id = 0;
    opts->flags   = 0;
    int err = bpf_tc_detach(hook, opts);
    if (err)
        fprintf(stderr, "[-] bpf_tc_detach: %s\n", strerror(-err));
}

static void usage(const char *argv0)
{
    fprintf(stderr, "Usage: %s <iface>\n", argv0);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        fprintf(stderr, "[-] Unknown interface '%s': %s\n", iface, strerror(errno));
        return EXIT_FAILURE;
    }

    /* Open and load the eBPF object */
    struct bpf_object *obj = bpf_object__open_file(MY_EBPF_OBJ, NULL);
    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "[-] bpf_object__open_file(%s) failed\n", MY_EBPF_OBJ);
        return EXIT_FAILURE;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "[-] bpf_object__load failed\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* Find programs by name */
    struct bpf_program *ingress_prog =
        bpf_object__find_program_by_name(obj, "udp_port_save");
    struct bpf_program *egress_prog =
        bpf_object__find_program_by_name(obj, "udp_port_rewrite");
    if (!ingress_prog || !egress_prog) {
        fprintf(stderr, "[-] eBPF program(s) not found in object\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    /* Handle Ctrl-C / SIGTERM so the filters get detached */
    struct sigaction sa = {};
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Attach ingress filter */
    struct bpf_tc_hook ingress_hook = {};
    struct bpf_tc_opts ingress_opts = {};
    if (tc_attach_bpf(ifindex, BPF_TC_INGRESS, bpf_program__fd(ingress_prog),
                      &ingress_hook, &ingress_opts) < 0) {
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] Ingress filter attached on %s\n", iface);

    /* Attach egress filter */
    struct bpf_tc_hook egress_hook = {};
    struct bpf_tc_opts egress_opts = {};
    if (tc_attach_bpf(ifindex, BPF_TC_EGRESS, bpf_program__fd(egress_prog),
                      &egress_hook, &egress_opts) < 0) {
        tc_detach_bpf(&ingress_hook, &ingress_opts);
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("[+] Egress filter attached on %s\n", iface);

    printf("Running - press Ctrl-C to detach and stop...\n");
    while (!g_stop)
        pause();

    /* Cleanup */
    printf("\n[*] Caught signal, detaching filters...\n");
    tc_detach_bpf(&egress_hook, &egress_opts);
    tc_detach_bpf(&ingress_hook, &ingress_opts);
    bpf_object__close(obj);
    return EXIT_SUCCESS;
}
