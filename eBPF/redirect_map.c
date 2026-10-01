#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Custom layout matching the target Geneve metadata format */
struct geneve_opt_custom {
    __be16  opt_class;
    __u8    type;
    __u8    length_rsvd; // Replaces the risky bitfield union
    __u32   opt_data;
};

/*
 * Route entry: new outer src/dst IPs for the re-encapsulated leg.
 * Written by user_control and read by the egress eBPF program.
 */
struct route_entry {
    __u32 local_ipv4;   // new outer source IP  (e.g. RELAY_RIGHT 10.0.1.2)
    __u32 remote_ipv4;  // new outer destination IP (e.g. RIGHT_UNDERLAY 10.0.1.3)
};

/*
 * Dynamic Routing Map:
 * Key   = Geneve option data value (__u32, host byte order)
 * Value = struct route_entry
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct route_entry);
} geneve_routes SEC(".maps");

/* ── Ingress program ──────────────────────────────────────────────────────────
 *
 * Attached to TC ingress of geneve-in.
 *
 * The Geneve driver has already decapsulated the packet and attached tunnel
 * metadata (VNI, outer IPs, Geneve options) to the skb before this runs.
 *
 */
SEC("tc/ingress")
int geneve_ingress_redirect(struct __sk_buff *skb)
{
    struct geneve_opt_custom opt = {};

    int len = bpf_skb_get_tunnel_opt(skb, &opt, sizeof(opt));
    if (len < (int)sizeof(struct geneve_opt_custom))
        return TC_ACT_OK;

    if (bpf_ntohs(opt.opt_class) != 0x0101 || opt.type != 0x2A)
        return TC_ACT_OK;

    __u32 opt_val = bpf_ntohl(opt.opt_data);

    bpf_printk("ingress: CB old mark: %d", skb->mark);
    skb->mark = opt_val;

    // opt_val 300 (0x12C) means local delivery — do not relay
    if (opt_val == 300)
        return TC_ACT_OK;

    // Read current tunnel key to preserve VNI and other fields
    struct bpf_tunnel_key cur_tkey = {};
    if (bpf_skb_get_tunnel_key(skb, &cur_tkey, sizeof(cur_tkey), 0) < 0) {
        bpf_printk("ingress: get_tunnel_key failed, dropping");
        return TC_ACT_SHOT;
    }
    bpf_printk("ingress: local_ip: %d remote_ipv: %d, vni: %d tl: %d", cur_tkey.local_ipv4, cur_tkey.remote_ipv4, cur_tkey.tunnel_id, cur_tkey.tunnel_ttl);

    // Redirect to this device's own egress path.
    // The egress eBPF program will rewrite the tunnel key
    bpf_printk("ingress: opt=%u, cloning/redirecting to egress ifindex %u",
               opt_val, skb->ifindex);

    int ret = bpf_redirect(skb->ifindex, 0); 
    if (ret != TC_ACT_REDIRECT) {
        bpf_printk("ingress: redirect failed");
    } else {
        bpf_printk("ingress: redirect OK");
    }
    return ret; 
}

/* ── Egress program ───────────────────────────────────────────────────────────
 *
 * Attached to TC egress of geneve-in at a lower pref (higher priority number)
 * than the "tunnel_key unset" TC filter, so it runs FIRST.
 */
SEC("tc/egress")
int geneve_egress_rewrite(struct __sk_buff *skb)
{
    struct geneve_opt_custom opt = {};
    struct route_entry default_route = {
        .remote_ipv4 = 0x0A000103,
        .local_ipv4 = 0x0A000102
    };

    __u32 my_opt = skb->mark;
    bpf_printk("egress: CB  mark: %d", my_opt);

    struct route_entry *route = bpf_map_lookup_elem(&geneve_routes, &my_opt);
    if (!route) {
        bpf_printk("egress: no route for opt=%u, using default", my_opt);
        route = &default_route;
        //return TC_ACT_SHOT;
    }

    struct bpf_tunnel_key tkey = {};
    tkey.remote_ipv4 = route->remote_ipv4;
    // tkey.local_ipv4 = route->local_ipv4;
    tkey.tunnel_id = 42;
    tkey.tunnel_ttl = 64;

    if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0) {
        bpf_printk("egress: set_tunnel_key failed, dropping");
        return TC_ACT_SHOT;
    }

    struct geneve_opt_custom gen_opt = {};
    gen_opt.opt_class = bpf_htons((0x0101));
    gen_opt.type = 0x2A;
    gen_opt.opt_data = bpf_htonl(my_opt);
    gen_opt.length_rsvd = 1 & 0x1F;

    int ret = bpf_skb_set_tunnel_opt(skb, &gen_opt, sizeof(gen_opt));
    if (ret < 0) {
        bpf_printk("egress: Failed to set Geneve option: %d\n", ret);
        return TC_ACT_SHOT; // Drop packet on error, or return TC_ACT_OK based on intent
    }

    bpf_printk("egress: packet completed (opt: %d)", my_opt);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
