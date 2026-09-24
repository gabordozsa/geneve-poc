#include <bpf/libbpf.h>
#include <arpa/inet.h>

// This regular C code for the control plane in user space to modify the routing map

void update_route(struct bpf_object *obj, uint32_t option_val, const char *ip_str) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "geneve_routes");
    int map_fd = bpf_map__fd(map);

    uint32_t key = option_val;
    uint32_t value;
    inet_pton(AF_INET, ip_str, &value); // Convert string IP to big-endian __u32

    // Atomically insert or update the value in kernel memory
    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
}
