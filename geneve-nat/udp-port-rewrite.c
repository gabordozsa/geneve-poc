#include <stddef.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Geneve UDP port (host byte order). Also used as the key of the port map. */
#define GENEVE_PORT 6081

/* IPv4 fragment bits in iphdr->frag_off (network byte order) */
#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

/*
 * Saved UDP source port
 * Key   = 6081 (the UDP destination port the ingress filter matched on), host byte order
 * Value = UDP source port seen in the last ingress packet with dest port 6081,
 *         network byte order
 *
 * Written by the ingress filter, read by the egress filter.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __be16);
} port_map SEC(".maps");

/*
 * Parse an Ethernet/IPv4/UDP packet. Returns a pointer to the UDP header
 * if the packet is a non-fragmented IPv4 UDP packet with destination port
 * GENEVE_PORT, NULL otherwise.
 */
static __always_inline struct udphdr *geneve_udp_hdr(struct __sk_buff *skb)
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

    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end)
        return NULL;
    if (udp->dest != bpf_htons(GENEVE_PORT))
        return NULL;

    return udp;
}

/* Ingress: save the source port of UDP packets sent to port 6081 */
SEC("tc/ingress")
int udp_port_save(struct __sk_buff *skb)
{
    struct udphdr *udp = geneve_udp_hdr(skb);
    if (!udp)
        return TC_ACT_OK;

    __u32 key = GENEVE_PORT;
    __be16 sport = udp->source;

    long ret = bpf_map_update_elem(&port_map, &key, &sport, BPF_ANY);
    if (ret < 0)
        bpf_printk("ingress: failed to save src port %u, error %ld", bpf_ntohs(sport), ret);
    else
        bpf_printk("ingress: saved src port %u for dst port %u", bpf_ntohs(sport), key);
    return TC_ACT_OK;
}

/* Egress: rewrite the dest port of UDP packets sent to port 6081 */
SEC("tc/egress")
int udp_port_rewrite(struct __sk_buff *skb)
{
    struct udphdr *udp = geneve_udp_hdr(skb);
    if (!udp)
        return TC_ACT_OK;

    __u32 key = GENEVE_PORT;
    __be16 *saved = bpf_map_lookup_elem(&port_map, &key);
    if (!saved) {
        bpf_printk("egress: no saved port, packet unchanged");
        return TC_ACT_OK; // nothing saved, leave the packet unchanged
    }

    __be16 old_port = udp->dest;
    __be16 new_port = *saved;
    if (new_port == old_port) {
        bpf_printk("egress: dst port already %u, packet unchanged", bpf_ntohs(old_port));
        return TC_ACT_OK;
    }

    /* Offsets must be computed before calling helpers that invalidate packet pointers */
    __u32 udp_off   = (void *)udp - (void *)(long)skb->data;
    __u32 dport_off = udp_off + offsetof(struct udphdr, dest);
    __u32 sport_off = udp_off + offsetof(struct udphdr, source);
    __u32 csum_off  = udp_off + offsetof(struct udphdr, check);

    /* Update the UDP checksum first (no BPF_F_PSEUDO_HDR: ports are not in the pseudo header;
     * the kernel leaves a CHECKSUM_PARTIAL offloaded checksum alone), then the port. */
    if (bpf_l4_csum_replace(skb, csum_off, old_port, new_port,
                            BPF_F_MARK_MANGLED_0 | sizeof(new_port)) < 0 ||
        bpf_skb_store_bytes(skb, dport_off, &new_port, sizeof(new_port), 0) < 0) {
        bpf_printk("egress: failed to rewrite dst port");
        return TC_ACT_OK;
    }
    __be16 new_sport = bpf_htons(GENEVE_PORT);
    if (bpf_skb_store_bytes(skb, sport_off, &new_sport, sizeof(new_sport), 0) < 0) {
        bpf_printk("egress: failed to rewrite src port");
        return TC_ACT_OK;
    }

    bpf_printk("egress: rewrote dst port %u -> %u", bpf_ntohs(old_port), bpf_ntohs(new_port));
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
