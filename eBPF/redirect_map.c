#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Custom layout matching the target Geneve metadata format */
struct geneve_opt_custom {
    __be16  opt_class;
    __u8    type;
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8    rsvd:3,
            length:5;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    length:5,
            rsvd:3;
#endif
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
 * Logic:
 *   - Read the Geneve option.  If class/type don't match, pass up normally.
 *   - If opt_data == 300 (0x12C): local delivery — pass to the stack (TC_ACT_OK).
 *   - Otherwise: redirect the packet to the EGRESS path of the same interface
 *     (bpf_redirect with flag 0 = egress).  The tunnel metadata is still
 *     attached to the skb and will be read by the egress eBPF program.
 *     No tunnel key modification is done here.
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

    // opt_val 300 (0x12C) means local delivery — do not relay
    if (opt_val == 300)
        return TC_ACT_OK;

    // Redirect to this device's own egress path.
    // The egress eBPF program will rewrite the tunnel key, then
    // the TC "tunnel_key unset" filter will commit it so the Geneve
    // driver builds the new outer header.
    bpf_printk("ingress: opt=%u, redirecting to egress ifindex %u",
               opt_val, skb->ifindex);
    return bpf_redirect(skb->ifindex, 0);
}

/* ── Egress program ───────────────────────────────────────────────────────────
 *
 * Attached to TC egress of geneve-in at a lower pref (higher priority number)
 * than the "tunnel_key unset" TC filter, so it runs FIRST.
 *
 * Must be attached with a lower pref value than the tunnel_key unset filter.
 * user_control attaches this eBPF at pref 1; the TC tunnel_key unset is
 * added at pref 2 via a shell command after user_control runs.
 *
 * Logic:
 *   - Read the Geneve option from the skb metadata (still present from ingress
 *     decap, carried through bpf_redirect).
 *   - Look up the new outer IPs in geneve_routes.
 *   - Call bpf_skb_set_tunnel_key to rewrite src/dst IPs (VNI and opts intact).
 *   - Return TC_ACT_PIPE so the next filter ("tunnel_key unset") runs and
 *     commits the metadata to the Geneve driver for re-encapsulation.
 */
SEC("tc/egress")
int geneve_egress_rewrite(struct __sk_buff *skb)
{
    struct geneve_opt_custom opt = {};

    // The tunnel metadata written during ingress decap is still present on
    // the skb after bpf_redirect to the same device's egress.
    int len = bpf_skb_get_tunnel_opt(skb, &opt, sizeof(opt));
    if (len < (int)sizeof(struct geneve_opt_custom)) {
        bpf_printk("egress: no tunnel opt, passing");
        return TC_ACT_OK;
    }

    if (bpf_ntohs(opt.opt_class) != 0x0101 || opt.type != 0x2A) {
        bpf_printk("egress: opt class/type mismatch, passing");
        return TC_ACT_OK;
    }

    __u32 opt_val = bpf_ntohl(opt.opt_data);

    struct route_entry *route = bpf_map_lookup_elem(&geneve_routes, &opt_val);
    if (!route) {
        bpf_printk("egress: no route for opt=%u, dropping", opt_val);
        return TC_ACT_SHOT;
    }

    // Read current tunnel key to preserve VNI and other fields
    struct bpf_tunnel_key tkey = {};
    if (bpf_skb_get_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0) {
        bpf_printk("egress: get_tunnel_key failed, dropping");
        return TC_ACT_SHOT;
    }
    bpf_printk("egress: local_ip: %d remote_ipv: %d, vni: %d tl: %d", tkey.local_ipv4, tkey.remote_ipv4, tkey.tunnel_id, tkey.tunnel_ttl);

    // Rewrite outer IPs only; VNI and Geneve opts are untouched
    tkey.local_ipv4  = route->local_ipv4;
    tkey.remote_ipv4 = route->remote_ipv4;

    if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), BPF_F_ZERO_CSUM_TX) < 0) {
        bpf_printk("egress: set_tunnel_key failed, dropping");
        return TC_ACT_SHOT;
    }

    bpf_printk("egress: opt=%u rewrote outer IPs, piping to tunnel_key unset",
               opt_val);

    // TC_ACT_PIPE: pass to the next filter in the egress chain.
    // The "tunnel_key unset" TC filter at the next pref will commit the
    // metadata so the Geneve driver builds the outer UDP/IP header.
    return TC_ACT_PIPE;
}

char _license[] SEC("license") = "GPL";
