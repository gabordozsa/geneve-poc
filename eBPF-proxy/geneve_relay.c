#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOG_INFO  1
#define LOG_ERROR 2

// Current log level
#define LOG_LEVEL LOG_ERROR

// virtual network ID
#define VNI 42

// Geneve TLV option calss and type
#define OPT_CLASS 0x0101
#define OPT_TYPE    0x2A

// Max number of proxies for map sizing. It is the sizeof(u8) which is the
// type of proxy index.
// Note that only 255 proxies are allowed in practice - index 0 is reserved
#define MAX_PROXIES 256

// Index value to signal the lack of dest/src ID-hash to recognize locally
// created packets in the egress filter
#define LOCAL_HASH_INDEX 0

/* Custom layout matching the target Geneve metadata format */
struct geneve_opt_custom {
    __be16  opt_class;
    __u8    type;
    __u8    length_rsvd; // Replaces the risky bitfield union
    __be32   opt_data[2]; // [dest ID hash][src ID hash]
};


/*
 * IP to ID-hash
 * Key   = inner (overlay) dest ip - network byte order
 * Value = dest proxy ID hash
 *
 * Note: IPs are defined and used locally at each proxy. They must be routed via the local geneve iface.
 * Used at egress for locally created packets to get dest ID hash = ip2hash(inner dest ip)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROXIES);
    __type(key, __be32);
    __type(value, __be32);
} ip2hash SEC(".maps");

/*
 * ID-hash to IP
 * Key   = overlay IP - network byte order
 * Value = proxy ID hash - network byte order
 *
 * Note: this the inverse mapping of ip2hash.
 * Used at ingress for packets to terminate: the inner src addres is replaced by id2ip(src ID-hash)
 * before delivering the packet locally.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROXIES);
    __type(key, __be32);
    __type(value, __be32);
} hash2ip SEC(".maps");

/*
 * ID-hash to next hop underlay IP
 * Key   = proxy ID-hash - network byte order
 * Value = next hop underlay IP - network byte order
 *
 * Note: get the next hop underlay (outer dest) IP for the dest ID-hash
 * Used at egress for each packet.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROXIES);
    __type(key, __be32);
    __type(value, __be32);
} hash2nh SEC(".maps");

/*
 * ID-hash to 8-bit unique local index
 * Key   = proxy ID-hash - network byte order
 * Value = unique local index
 *
 * Note: used at ingress to pass dest and src ID-hash values to egress
 * using the upper 16-bits of fwmark.
 * Used at egress for each packet.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROXIES);
    __type(key, __be32);
    __type(value, __u8);
} hash2ind SEC(".maps");

/*
 * 8-bit unique local index to ID-hash
 * Key   = proxy ID-hash - network byte order
 * Value = unique local index
 *
 * Note: Inverse map of hash2ind. Used at egress to recover dest and sec ID-hash 
 * from the uppper 16-bits of fwmark.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROXIES);
    __type(key, __u8);
    __type(value, __be32);
} ind2hash SEC(".maps");

/* Global variables set from user-space at load-time */
const volatile __be32 LOCAL_ID_HASH;
const volatile __be32 LOCAL_OVERLAY_IP;

// Log messages are written to /sys/kernel/tracing/trace
#define log(level, fmt, args...) if (level >= LOG_LEVEL) bpf_printk("[%08x] " fmt, LOCAL_ID_HASH, ##args)

/* Ingress: packet reached its final destination */
static __always_inline int local_ingress_packet(struct __sk_buff *skb, __be32 src_id_hash) {
    // Get the locally assigned overlay ip for the src_id_hash
    __be32 *src_ip_ptr = bpf_map_lookup_elem(&hash2ip, &src_id_hash);
    if (!src_ip_ptr) {
        log(LOG_ERROR,"ingress: no local ip for src proxy ID hash %08x, dropping", bpf_ntohl(src_id_hash));
        return TC_ACT_SHOT;
    }
    __be32 new_src_ip = *src_ip_ptr;

    // Re-write the inner src address. This will make any reply packet use it as inner dest IP so,
    // the egress filter will be able to find the corresponding dest ID hash.
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        log(LOG_ERROR,"(E) ingress: eth header is missing, dropping");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        log(LOG_ERROR,"(E) ingress: not an ipv4 packet, eth->h_proto: %x, dropping", eth->h_proto);
        return TC_ACT_SHOT;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        log(LOG_ERROR,"(E) ingress: ip header is missing, dropping");
        return TC_ACT_SHOT;
    }

    log(LOG_INFO, "ingress: old saddr %08x daddr %08x", ip->saddr, ip->daddr);

    __be32 old_addr[2] = { ip->saddr, ip->daddr };
    __be32 new_addr[2] = { new_src_ip, LOCAL_OVERLAY_IP };

    ip->saddr = new_src_ip;       // new inner src address
    ip->daddr = LOCAL_OVERLAY_IP; // new inner dst address

    log(LOG_INFO, "ingress: new saddr %08x daddr %08x", new_src_ip, LOCAL_OVERLAY_IP);

    // Fix layer 3 checksum
    __s64 csum_diff = bpf_csum_diff(old_addr, sizeof(old_addr), new_addr, sizeof(new_addr), 0);
    if (csum_diff < 0) {
        log(LOG_ERROR,"(E) ingress:bpf_csum_diff() error: %lld, dropping", csum_diff);
        return TC_ACT_SHOT;
    }

    __u32 l3_csum_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, check);

    int ret = bpf_l3_csum_replace(skb, l3_csum_offset, 0, csum_diff, 0);
    if (ret < 0) {
        log(LOG_ERROR,"(E) ingress: pf_l3_csum_replace() error: %d, dropping", ret);
        return TC_ACT_SHOT;
    }

    // Need to reload data/data_end and re-derive pointers because the BPF verifier
    // considers bpf_l3_csum_replace() to potentially invalidate packet pointers.
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;

    eth = data;
    if ((void *)(eth + 1) > data_end) {
        log(LOG_ERROR,"(E) ingress: eth header missing after L3 csum fix, dropping");
        return TC_ACT_SHOT;
    }

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        log(LOG_ERROR,"(E) ingress: ip header is missing after L3 csum fix, dropping");
        return TC_ACT_SHOT;
    }

    __u32 l4_csum_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (ip->protocol == IPPROTO_TCP) {
        l4_csum_offset += offsetof(struct tcphdr, check);

        // Pass the precomputed diff. Set from and four lowest bits of flags to 0 to
        // indicate that to is the csum diff value. BPF_F_PSEUDO_HDR indicates that the modfied
        // vslue is part of the pseudo header.
        ret = bpf_l4_csum_replace(skb, l4_csum_offset, 0, csum_diff, BPF_F_PSEUDO_HDR);
        if (ret < 0) {
            log(LOG_ERROR,"(E) ingress: bpf_l4_csum_replace() TCP error: %d, dropping", ret);
            return TC_ACT_SHOT;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        l4_csum_offset += offsetof(struct udphdr, check);
        // Read the current UDP checksum to ensure it isn't 0
        // (UDP checksums are optional in IPv4; 0 means disabled)
        __be16 udp_check;
        ret = bpf_skb_load_bytes(skb, l4_csum_offset, &udp_check, sizeof(udp_check));
        if (ret < 0) {
            log(LOG_ERROR,"(E) ingress: could not read  old UDP csum, error: %d, dropping", ret);
            return TC_ACT_SHOT;
        }
        if (udp_check > 0) {
            ret = bpf_l4_csum_replace(skb, l4_csum_offset, 0, csum_diff, BPF_F_PSEUDO_HDR);
            if (ret < 0) {
                log(LOG_ERROR,"(E) ingress: bpf_l4_csum_replace() UDP error: %d, dropping", ret);
                return TC_ACT_SHOT;
            }
        } else {
            log(LOG_ERROR,"(I) ingress: old UDP csum is zero, skip csum fixing");
        }
    }

    log(LOG_INFO, "ingress: local packet is being delivered");
    return TC_ACT_OK; // deliver the packet locally
}

/* Ingress: relay packet */
static __always_inline int relay_ingress_packet(struct __sk_buff *skb, __be32 dst_id_hash, __be32 src_id_hash) {
    __u8 *hash_index_ptr = bpf_map_lookup_elem(&hash2ind, &dst_id_hash);
    if(!hash_index_ptr) {
        log(LOG_ERROR,"(E) ingress: no index for dst ID hash %08x, dropping", dst_id_hash);
        return TC_ACT_SHOT;
    }
    __u8 dst_hash_index = *hash_index_ptr;
    hash_index_ptr = bpf_map_lookup_elem(&hash2ind, &src_id_hash);
    if(!hash_index_ptr) {
        log(LOG_ERROR,"(E) ingress: no index for src ID hash %08x, dropping", src_id_hash);
        return TC_ACT_SHOT;
    }
    __u8 src_hash_index = *hash_index_ptr;

    // Pass hash indices to egress filter using the upper 16 bits of skb->mark
    // FIXME: this may cause problems if mark is already in use. More robust solution would be:
    // pass the info via another ebpf map where the key is an incremented counter modulo map size.
    // (I.e. use map as producer/consumer queue ...)
    if (skb->mark >> 16) {
        log(LOG_ERROR,"(E) ingress: upper 16 bits of skb->mark %08x is not zero, droppoing", skb->mark);
        return TC_ACT_SHOT;
    }
    skb->mark |= (dst_hash_index << 24) | (src_hash_index << 16);

    int ret = bpf_redirect(skb->ifindex, 0); 
    if (ret != TC_ACT_REDIRECT) {
        log(LOG_ERROR,"(E) ingress: redirect failed");
    } else {
        log(LOG_INFO,"ingress: redirect OK");
    }
    return ret;
}

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
    // DEBUG
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        log(LOG_ERROR,"(E) ingress: eth header is missing, dropping");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        log(LOG_ERROR,"(E) ingress: not an ipv4 packet, eth->h_proto: %x, dropping", eth->h_proto);
        return TC_ACT_SHOT;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        log(LOG_ERROR,"(E) ingress: ip header is missing, dropping");
        return TC_ACT_SHOT;
    }

    log(LOG_INFO, "ingress: old saddr %08x daddr %08x", ip->saddr, ip->daddr);
    // DBUG END


    struct geneve_opt_custom opt = {};

    int len = bpf_skb_get_tunnel_opt(skb, &opt, sizeof(opt));
    if (len < (int)sizeof(struct geneve_opt_custom)) {
        log(LOG_ERROR,"ingress: Could not read geneve opts, dropping");
        return TC_ACT_SHOT;
    }

    if (bpf_ntohs(opt.opt_class) != OPT_CLASS || opt.type != OPT_TYPE) {
        log(LOG_ERROR,"ingress: Unknown opt class or type. Expected %04x/%02x got %04x/%02x, dropping", 
        bpf_htons(OPT_CLASS), OPT_TYPE, bpf_ntohs(opt.opt_class), opt.type);
        return TC_ACT_SHOT;
    }
    __be32 dst_id_hash = opt.opt_data[0];
    __be32 src_id_hash = opt.opt_data[1];

    log(LOG_INFO,"ingress: dest proxy ID hash %08x source proxy ID hash %08x", 
        bpf_ntohl(dst_id_hash), bpf_ntohl(src_id_hash));

    if (dst_id_hash == LOCAL_ID_HASH) {
        log(LOG_INFO, "ingress: local ingress packet");
        // Packet reached its final destination
        return local_ingress_packet(skb, src_id_hash);
    }

    // Relay packet
    log(LOG_INFO, "ingress: relay ingress packet");
    return relay_ingress_packet(skb, dst_id_hash, src_id_hash);
}

// set tunnel key and opt at egress
static __always_inline int set_tunnel_key_and_opt(struct __sk_buff *skb, __be32 nh_ip,
                                                  __be32 dest_id_hash, __be32 src_id_hash) {
    struct bpf_tunnel_key tkey = {};
    tkey.remote_ipv4 = nh_ip;
    // tkey.local_ipv4 = ... No need, this is set by the driver based on the rout src
    tkey.tunnel_id = VNI;
    tkey.tunnel_ttl = 64; // FIXME: this should come from ingress ,,,,

    if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), 0) < 0) {
        log(LOG_ERROR,": set_tunnel_key_and_opt((): set_tunnel_key failed, dropping");
        return TC_ACT_SHOT;
    }

    struct geneve_opt_custom gen_opt = {};
    gen_opt.opt_class = bpf_htons((OPT_CLASS));
    gen_opt.type = OPT_TYPE;
    gen_opt.opt_data[0] = dest_id_hash;
    gen_opt.opt_data[1] = src_id_hash;
    gen_opt.length_rsvd = 2 & 0x1F;

    int ret = bpf_skb_set_tunnel_opt(skb, &gen_opt, sizeof(gen_opt));
    if (ret < 0) {
        log(LOG_ERROR,"et_tunnel_key_and_opt(): Failed to set Geneve option, ret: %d, dropping", ret);
        return TC_ACT_SHOT; 
    }
    return TC_ACT_OK;
}


// Locally created egress packet
static __always_inline int local_egress_packet(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        log(LOG_ERROR,"(E) local_egress_packet(): eth header is missing");
        return TC_ACT_SHOT;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        log(LOG_ERROR,"(E) local_egress_packet(): no ipv4 packet, eth->h_proto: %x", eth->h_proto);
        return TC_ACT_SHOT;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        log(LOG_ERROR,"(E) local_egress_packet(): ip header is missing");
        return TC_ACT_SHOT;
    }

    __be32 old_daddr = ip->daddr; // inner dest addr
    log(LOG_INFO,"local_egress_packet(): old ip: %08x", old_daddr);
    // Get the ID hash of the dest proxy
    __be32 *id_hash_ptr = bpf_map_lookup_elem(&ip2hash, &old_daddr);
    if (!id_hash_ptr) {
        log(LOG_ERROR,"(E) local_egress_packet(): no dest ID hash for dest ip: %08x", old_daddr);
        return TC_ACT_SHOT;
    }
    __be32 dest_id_hash = *id_hash_ptr;
    log(LOG_INFO,"(I) local_egress_packet(): dest id_hash: %08x", bpf_ntohl(dest_id_hash));

    // Get the underlay IP of the next hop
    __be32 *nh_ip_ptr = bpf_map_lookup_elem(&hash2nh, &dest_id_hash);
    if (!nh_ip_ptr) {
        log(LOG_ERROR,"(E) local_egress_packet(): no next hop IP for old dest ID hash: %08x", bpf_ntohl(dest_id_hash));
        return TC_ACT_SHOT;
    }
    __be32 nh_ip = *nh_ip_ptr;
    __be32 src_id_hash = LOCAL_ID_HASH;

    return set_tunnel_key_and_opt(skb, nh_ip, dest_id_hash, src_id_hash);
}

// Relay egress packet
static __always_inline int relay_egress_packet(struct __sk_buff *skb, __u8 dst_hash_index, __u8 src_hash_index) {
    // Get the ID hash of the dest proxy
    __be32 *id_hash_ptr = bpf_map_lookup_elem(&ind2hash, &dst_hash_index);
    if (!id_hash_ptr) {
        log(LOG_ERROR,"(E) relay_egress_packet(): no dest ID hash for index: %d, dropping", dst_hash_index);
        return TC_ACT_SHOT;
    }
    __be32 dest_id_hash = *id_hash_ptr;

    // Get the ID hash of the src proxy
    id_hash_ptr = bpf_map_lookup_elem(&ind2hash, &src_hash_index);
    if (!id_hash_ptr) {
        log(LOG_ERROR,"(E) relay_egress_packet(): no src ID hash for index: %d, dropping", src_hash_index);
        return TC_ACT_SHOT;
    }
     __be32 src_id_hash = *id_hash_ptr;

    // Get the underlay IP of the next hop
    __be32 *nh_ip_ptr = bpf_map_lookup_elem(&hash2nh, &dest_id_hash);
    if (!nh_ip_ptr) {
        log(LOG_ERROR,"(E) relay_egress_packet(): no next hop IP for old dest ID hash: %08x", bpf_ntohl(dest_id_hash));
        return TC_ACT_SHOT;
    }
    __be32 nh_ip = *nh_ip_ptr;

    log(LOG_INFO,"(I) relay_egress_packet(): dest id_hash: %08x src id_hash: %08x", bpf_ntohl(dest_id_hash), bpf_ntohl(src_id_hash));
    return set_tunnel_key_and_opt(skb, nh_ip, dest_id_hash, src_id_hash);
}

/* ── Egress program ───────────────────────────────────────────────────────────
 *
 * Attached to TC egress of geneve-in at a lower pref (higher priority number)
 * than the "tunnel_key unset" TC filter, so it runs FIRST.
 */
SEC("tc/egress")
int geneve_egress_rewrite(struct __sk_buff *skb)
{
    /*
    struct route_entry default_route = {
        .remote_ipv4 = 0x0A000103,
        .local_ipv4 = 0x0A000102
    };
    */

    __u8 dst_hash_index = (skb->mark >> 24);
    __u8 src_hash_index =  (skb->mark >> 16 & 0xFF);
    log(LOG_INFO,"egress: CB  mark: %d dst/src hash index: %d/%d", skb->mark,  dst_hash_index, src_hash_index);

    if (dst_hash_index == 0) {
        // Locally created packet
        if (src_hash_index != 0) {
            log(LOG_ERROR,"(E) dst hash index is zero but src hash index is %d. Dropping ...", src_hash_index);
            return TC_ACT_SHOT;
        }
        return local_egress_packet(skb);
    }

    // Packet to forward
    return relay_egress_packet(skb, dst_hash_index, src_hash_index);
}

char _license[] SEC("license") = "GPL";
