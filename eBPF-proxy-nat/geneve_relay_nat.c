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
#define LOG_LEVEL LOG_INFO

// virtual network ID (must be less than 256 to fit into a dingle byte)
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

/*
 * Geneve base header (RFC 8926), 8 bytes. Endianness-agnostic: the sub-byte
 * fields are packed into whole bytes and accessed with the masks/shifts below
 * instead of C bitfields.
 *
 * ver_optlen: Ver (2 bits) | Opt Len (6 bits, in 4-byte words)
 * flags:      O (1 bit) | C (1 bit) | Rsvd (6 bits)
 */
#define GENEVE_VER_SHIFT      6
#define GENEVE_OPT_LEN_MASK   0x3F
#define GENEVE_FLAG_OAM       0x80
#define GENEVE_FLAG_CRITICAL  0x40

struct genevehdr {
    __u8   ver_optlen;
    __u8   flags;
    __be16 proto_type;   // e.g. ETH_P_TEB (0x6558) for Ethernet payload
    __u8   vni[3];
    __u8   rsvd2;
    // Variable-length options follow (opt_len * 4 bytes)
} __attribute__((packed));

#define GENEVE_OPT_DATA_LEN_MASK 0x1F

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
 * Value = next hop underlay IP + port - network byte order
 *
 * Note: the nh ip and the port is saved at ingress. This is necessary for provate site and
 * possible NAT/conntrack. 
 *
 * Used at egress for each packet.
 */
 typedef struct nh_port {
    __be32 nh;
    __be16 port;
 } nh_port;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROXIES);
    __type(key, __be32);
    __type(value, nh_port);
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

    /*
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        log(LOG_ERROR,"(E) ingress: eth header is missing, dropping");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        log(LOG_INFO,"(E) ingress: not an ipv4 packet, eth->h_proto: %x, dropping", eth->h_proto);
        return TC_ACT_SHOT;
    }

    struct iphdr *ip = (void *)(eth + 1);
    */
    struct iphdr *ip = data;
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

    // geneve0 is an L3 device (innerprotoinherit): no Ethernet header, packet starts at the IP header
    __u32 l3_csum_offset = offsetof(struct iphdr, check);

    int ret = bpf_l3_csum_replace(skb, l3_csum_offset, 0, csum_diff, 0);
    if (ret < 0) {
        log(LOG_ERROR,"(E) ingress: pf_l3_csum_replace() error: %d, dropping", ret);
        return TC_ACT_SHOT;
    }

    // Need to reload data/data_end and re-derive pointers because the BPF verifier
    // considers bpf_l3_csum_replace() to potentially invalidate packet pointers.
    data_end = (void *)(long)skb->data_end;
    data     = (void *)(long)skb->data;

    ip = data;
    if ((void *)(ip + 1) > data_end) {
        log(LOG_ERROR,"(E) ingress: ip header is missing after L3 csum fix, dropping");
        return TC_ACT_SHOT;
    }

    // TODO : check if the csum replace is really necessary here ...

    __u32 l4_csum_offset = sizeof(struct iphdr);

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
        log(LOG_ERROR,"(E) ingress: upper 16 bits of skb->mark %08x is not zero, dropping", skb->mark);
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
    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        log(LOG_ERROR, "(E) ingress: inner protocol %02x is not ipv4, dropping ...", bpf_ntohs(skb->protocol));
        return TC_ACT_SHOT;
    }

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

    struct iphdr *ip = data;
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
    nh_port *nh_port_ptr = bpf_map_lookup_elem(&hash2nh, &dest_id_hash);
    if (!nh_port_ptr) {
        log(LOG_ERROR,"(W) local_egress_packet(): no next hop IP (yet ?) for dest ID hash: %08x, dropping ...", 
            bpf_ntohl(dest_id_hash));
        return TC_ACT_SHOT;
    }
    __be32 nh_ip = nh_port_ptr->nh;
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
    nh_port *nh_port_ptr = bpf_map_lookup_elem(&hash2nh, &dest_id_hash);
    if (!nh_port_ptr) {
        log(LOG_ERROR,"(W) relay_egress_packet(): no next hop IP (yet ?) for dest ID hash: %08x", bpf_ntohl(dest_id_hash));
        return TC_ACT_SHOT;
    }
    __be32 nh_ip = nh_port_ptr->nh;

    log(LOG_INFO,"(I) relay_egress_packet(): dest id_hash: %08x src id_hash: %08x nh_ip: %08x", 
        bpf_ntohl(dest_id_hash), bpf_ntohl(src_id_hash),  bpf_ntohl(nh_ip));
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
    /* DEBUG
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        log(LOG_ERROR,"(E) egress: eth header is missing");
        return TC_ACT_SHOT;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        log(LOG_INFO,"(I) egress: not an ipv4 packet, eth->h_proto: %02x , dropping", eth->h_proto);
        return TC_ACT_SHOT;
    }
    bpf_printk("(I) egress: eth h_source %02x:%02x:%02x:%02x:%02x:%02x h_dest %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],  eth->h_source[3], eth->h_source[4], eth->h_source[5],
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // DEBUG */

    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        log(LOG_ERROR, "(E) egress: inner protocol %02x is not ipv4, dropping ...", bpf_ntohs(skb->protocol));
        return TC_ACT_SHOT;
    }

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

/*********************************************************************/
/*    UDP iface filters to handle private sites and NAT/conntrack    */
/*********************************************************************/

/* Geneve UDP port (host byte order). Also used as the key of the port map. */
#define GENEVE_PORT 6081

/* IPv4 fragment bits in iphdr->frag_off (network byte order) */
#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

/*
 * Saved UDP source port
 * Key   = source IP, host byte order
 * Value = UDP source port seen in the last ingress packet with dest port 6081,
 *         network byte order
 *
 * Written by the ingress filter, read by the egress filter.
 */
 /*
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __be32);
} port_map SEC(".maps");
*/

/*
 * Parse an Ethernet/IPv4/UDP packet. Returns a pointer to the UDP header
 * if the packet is a non-fragmented IPv4 UDP packet with destination port
 * GENEVE_PORT, NULL otherwise.
 */
static __always_inline struct udphdr *geneve_udp_hdr(struct __sk_buff *skb, __be32 *saddr, __be32 *daddr, __be32 *src_id_hash, __be32 *dst_id_hash)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return NULL;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return NULL;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return NULL;
    if (ip->protocol != IPPROTO_UDP)
        return NULL;
    if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
        return NULL; // UDP header is only in the first fragment

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return NULL;

    *saddr = ip->saddr;
    *daddr = ip->daddr;

    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end)
        return NULL;
    if (udp->dest != bpf_htons(GENEVE_PORT))
        return NULL;

    // Check if the packet has the expected Geneve option
    // TODO : make this simpler: only check if inner source IP == LOCAL_OVERLAY_IP (which is common for all sites)
    // That would make it sure that it is a Geneve packet from one of our Geneve iface ....
    struct genevehdr *gen = (void *)(udp + 1);
    struct geneve_opt_custom *opt = (void *)(gen + 1);
    struct iphdr *inner_ip = (void *)(opt + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return NULL;

    if (gen->vni[2] != VNI || gen->vni[1] !=0 || gen->vni[0] != 0) {
        bpf_printk("(W) udp geneve_udp_hdr(): vni missmatch vni[0]: %u vni[1]: %u vni[2]: %u", gen->vni[0], gen->vni[1], gen->vni[2]);
        return NULL;
    }
    if ((gen->ver_optlen >> GENEVE_VER_SHIFT) ||  (gen->ver_optlen &  GENEVE_OPT_LEN_MASK) != sizeof(struct geneve_opt_custom) / 4) {
        bpf_printk("(W) udp geneve_udp_hdr(): ver_optlen missmatch, ver: %u opt len: %u, ",
            gen->ver_optlen >> GENEVE_VER_SHIFT, gen->ver_optlen &  GENEVE_OPT_LEN_MASK);
            return NULL;
    }
    if (opt->opt_class != OPT_CLASS || opt->type != OPT_TYPE || (opt->length_rsvd & GENEVE_OPT_DATA_LEN_MASK) != 2) {
        bpf_printk("(W) udp geneve_udp_hdr(): optiona data length missmatch, lenght_rsvd: %02x", opt->length_rsvd);
        return NULL;
    }
    if (inner_ip->saddr != LOCAL_OVERLAY_IP) {
        bpf_printk("(W) udp geneve_udp_hdr(): inner source ip missmatch, inner daddr: %08xx", bpf_ntohl(inner_ip->saddr));
        return NULL;
    }

    // Option layout is [dest ID hash][src ID hash]
    *dst_id_hash = opt->opt_data[0];
    *src_id_hash = opt->opt_data[1];

    return udp;
}

/* Ingress: save the source port of UDP packets sent to port 6081 */
SEC("tc/ingress")
int udp_port_save(struct __sk_buff *skb)
{
    __be32 saddr, daddr, src_id_hash, dst_id_hash;
    struct udphdr *udp = geneve_udp_hdr(skb, &saddr, &daddr, &src_id_hash, &dst_id_hash);
    if (!udp)
        return TC_ACT_OK; // not our Geneve packet

    nh_port *nh_port_ptr = bpf_map_lookup_elem(&hash2nh, &src_id_hash);
    if (!nh_port_ptr || nh_port_ptr->nh != saddr || nh_port_ptr->port != udp->source) {
        bpf_printk("udp ingress: Updating hash2nh, id hash: %08x saddr: %08x -> %08x port: %u -> %u",
                    src_id_hash,
                    nh_port_ptr ? bpf_ntohl(nh_port_ptr->nh) : 0,
                    nh_port_ptr ? bpf_ntohs(nh_port_ptr->port) : 0);
        nh_port nhp = { saddr, udp->source };
        long ret = bpf_map_update_elem(&hash2nh, &src_id_hash, &nhp, BPF_ANY);
        if (ret < 0) {
          bpf_printk("ingress: failed to update nh_port for ID hash %08x, saddr %08x port %u, error %ld", 
           bpf_ntohl(src_id_hash), bpf_ntohl(saddr), bpf_ntohs(udp->source), ret);
          return TC_ACT_SHOT;
        }
        bpf_printk("ingress: saved addr %08x and port %04x for id hash: %u", 
            bpf_ntohl(saddr), bpf_ntohs(udp->source),bpf_ntohl(src_id_hash));
    }

    bpf_printk("udp ingress: done");

    return TC_ACT_OK;
}

/* Egress: rewrite the dest port of UDP packets sent to port 6081 */
SEC("tc/egress")
int udp_port_rewrite(struct __sk_buff *skb)
{
    __be32 saddr, daddr, src_id_hash, dst_id_hash;
    struct udphdr *udp = geneve_udp_hdr(skb, &saddr, &daddr, &src_id_hash, &dst_id_hash);
    if (!udp)
        return TC_ACT_OK; // not our Geneve packet

    // Only change UDP packets targeting known (Geneve) peers
    // If the peer is public then user_control adds it to the hash2nh map with port 6081
    // If the peer is private then ingress must add its address and port to the map first
    nh_port *nh_port_ptr = bpf_map_lookup_elem(&hash2nh, &dst_id_hash);
    if (!nh_port_ptr) {
        bpf_printk("udp egress: no saved peer nh and port for id hash %u, dropping ...", bpf_ntohl(dst_id_hash));
        return TC_ACT_SHOT; // nh and port not known (yet)
    }

    __u32 udp_off   = (void *)udp - (void *)(long)skb->data;
    __u32 csum_off  = udp_off + offsetof(struct udphdr, check);

    // Always change the souce port when sending to known Geneve peers
    __be16 old_port = udp->source;
    __be16 new_port = bpf_htons(GENEVE_PORT);
    udp->source = new_port;
    if (udp->check) {
        if (bpf_l4_csum_replace(skb, csum_off, old_port, new_port,
                            BPF_F_MARK_MANGLED_0 | sizeof(new_port)) < 0) {
            bpf_printk("egress: checksum failed for source port change");
            return TC_ACT_SHOT;
        }
    }
    bpf_printk("egress: src port changed to %u", GENEVE_PORT);

    // Need to re-validate udp pointer after calling bpf_l4_csum_replace()
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
         log(LOG_ERROR, "udp egress: FATAL eth header");
        return TC_ACT_SHOT;;
    }
    //if (eth->h_proto != bpf_htons(ETH_P_IP))
    //    return NULL;

    struct iphdr *ip = (void *)(eth + 1);
     if ((void *)(ip + 1) > data_end) {
        log(LOG_ERROR, "udp egress: FATAL ip header 1");
        return TC_ACT_SHOT;
     }
    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip)) {
        log(LOG_ERROR, "udp egress: FATAL ip header 2");
        return TC_ACT_SHOT;
    }

    udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end) {
        log(LOG_ERROR, "udp egress: FATAL udp header");
        return TC_ACT_SHOT;
    }

    // Change the dest port back to the original if there is NAT/conntrack, i.e. if
    // the ingress packet had a source port different from 6081.
    old_port = udp->dest;
    new_port = nh_port_ptr->port;
    if (new_port == old_port) {
        bpf_printk("egress: dst port already %u, packet unchanged", bpf_ntohs(old_port));
        return TC_ACT_OK;
    }

    udp->dest = new_port;

    if (udp->check) {
        if (bpf_l4_csum_replace(skb, csum_off, old_port, new_port,
                            BPF_F_MARK_MANGLED_0 | sizeof(new_port)) < 0) {
            bpf_printk("egress: checksum failed for dst port change");
            return TC_ACT_SHOT;
        }
    }

    bpf_printk("egress: rewrote dst port %u -> %u", bpf_ntohs(old_port), bpf_ntohs(new_port));
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
