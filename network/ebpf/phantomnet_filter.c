/*
 * PHANTOMNET — eBPF Packet Filter
 * Kernel-level XDP program for high-speed packet inspection.
 * Marks suspicious packets for userspace analysis.
 *
 * Build:
 *   clang -O2 -target bpf -c phantomnet_filter.c -o phantomnet_filter.o
 *   ip link set dev eth0 xdp obj phantomnet_filter.o sec xdp_filter
 *
 * Requires: Linux kernel 5.15+, clang, libbpf-dev
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ── Shared map: suspicious source IPs flagged for deep inspection ── */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);   /* IPv4 source address */
    __type(value, __u64);   /* Packet count from this IP */
    __uint(max_entries, 4096);
} suspect_ips SEC(".maps");

/* ── Shared map: per-IP SYN counter for scan detection ── */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   __u32);   /* IPv4 source address */
    __type(value, __u32);   /* SYN count */
    __uint(max_entries, 4096);
} syn_counters SEC(".maps");

/* ── Perf event map: send packet metadata to userspace ── */
struct pkt_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  tcp_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* Scan threshold: more than 100 SYNs from one IP → flag as scanner */
#define SYN_SCAN_THRESHOLD 100

SEC("xdp_filter")
int phantomnet_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    /* Parse IPv4 header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;

    struct pkt_event evt = {};
    evt.src_ip   = src_ip;
    evt.dst_ip   = dst_ip;
    evt.protocol = ip->protocol;

    /* ── TCP ── */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        evt.src_port  = bpf_ntohs(tcp->source);
        evt.dst_port  = bpf_ntohs(tcp->dest);
        evt.tcp_flags = (tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) |
                         (tcp->psh << 3) | (tcp->ack << 4) | (tcp->urg << 5));

        /* Track SYN packets for scan detection */
        if (tcp->syn && !tcp->ack) {
            __u32 *syn_cnt = bpf_map_lookup_elem(&syn_counters, &src_ip);
            if (syn_cnt) {
                __sync_fetch_and_add(syn_cnt, 1);
                if (*syn_cnt > SYN_SCAN_THRESHOLD) {
                    /* Mark as suspect */
                    __u64 one = 1;
                    bpf_map_update_elem(&suspect_ips, &src_ip, &one, BPF_ANY);
                }
            } else {
                __u32 init_val = 1;
                bpf_map_update_elem(&syn_counters, &src_ip, &init_val, BPF_NOEXIST);
            }
        }
    }

    /* ── UDP ── */
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        evt.src_port = bpf_ntohs(udp->source);
        evt.dst_port = bpf_ntohs(udp->dest);
    }

    /* ── ICMP ── */
    else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
        if ((void *)(icmp + 1) > data_end)
            return XDP_PASS;
        /* ICMP echo requests used for ping sweeps */
        if (icmp->type == ICMP_ECHO) {
            __u64 one = 1;
            __u64 *cnt = bpf_map_lookup_elem(&suspect_ips, &src_ip);
            if (cnt)
                __sync_fetch_and_add(cnt, 1);
            else
                bpf_map_update_elem(&suspect_ips, &src_ip, &one, BPF_NOEXIST);
        }
    }

    /* Send event to userspace perf buffer */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return XDP_PASS;   /* Always pass — we observe, not drop */
}

char _license[] SEC("license") = "GPL";
