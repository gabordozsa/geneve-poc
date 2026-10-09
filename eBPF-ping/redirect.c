#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Match the exact memory layout of your expected Geneve metadata layout */
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
    __u32   opt_data; // Assuming your option data is a 4-byte/32-bit field
};

SEC("classifier")
int geneve_ingress_redirect(struct __sk_buff *skb)
{
    struct geneve_opt_custom opt = {};
    struct bpf_tunnel_key tkey = {};

    // 1. Extract the Geneve Options payload from metadata context
    int len = bpf_skb_get_tunnel_opt(skb, &opt, sizeof(opt));
    if (len < (int)sizeof(struct geneve_opt_custom)) {
        return TC_ACT_OK; // Missing or short option data; pass packet up the stack
    }

    // Target tracking criteria (Example: Class 0x0101, Type 0x2A)
    if (bpf_ntohs(opt.opt_class) != 0x0101 || opt.type != 0x2A) {
        return TC_ACT_OK;
    }

    // 2. Clear out existing tunnel keys to overwrite them safely
    bpf_skb_clear_tunnel_key(skb);

    // 3. Map the option data value to your new remote destination IP
    __u32 custom_val = bpf_ntohl(opt.opt_data);
    __u32 target_dest_ip;

    if (custom_val == 100) {
        target_dest_ip = bpf_htonl(192, 168, 1, 10); // Node A
    } else if (custom_val == 200) {
        target_dest_ip = bpf_htonl(192, 168, 1, 20); // Node B
    } else {
        target_dest_ip = bpf_htonl(192, 168, 1, 30); // Default Fallback Node
    }

    // 4. Extract the existing VNI/Tunnel ID so it remains unmodified
    struct bpf_tunnel_key current_key = {};
    if (bpf_skb_get_tunnel_key(skb, &current_key, sizeof(current_key), 0) == 0) {
        tkey.tunnel_id = current_key.tunnel_id;
    } else {
        tkey.tunnel_id = 42; // Hardcoded default fallback VNI if get fails
    }

    // 5. Build and attach the new tunnel redirection parameters
    tkey.remote_ipv4 = target_dest_ip;
    tkey.tunnel_ttl = 64; 

    if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), BPF_F_ZERO_CSUM_TX) < 0) {
        return TC_ACT_SHOT; // Drop packet if we fail to map the new tunnel keys
    }

    // 6. Redirect the modified packet out via the egress of the same interface
    // skb->ifindex contains the interface ID it arrived on (your Geneve link)
    return bpf_redirect(skb->ifindex, 0); 
}

char _license[] SEC("license") = "GPL";
