// Drop only ICMPv4 packets. Pass everything else.
// Shows a printk line in trace_pipe when an ICMP is dropped.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>     // SEC(), bpf_printk()
#include <bpf/bpf_endian.h>      // __bpf_htons(), __bpf_ntohs()
#include <linux/if_ether.h>      // ETH_P_*
#include <linux/ip.h>            // struct iphdr
#include <linux/in.h>            // IPPROTO_ICMP

SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx)
{
    // XDP gives you raw packet pointers via ctx
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse L2 (Ethernet) header safely
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        // Truncated Ethernet header: let kernel handle it
        return XDP_PASS;
    }

    // Only handle IPv4 frames (EtherType 0x0800)
    if (eth->h_proto == __bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);

        // Bounds check IPv4 header
        if ((void *)(ip + 1) > data_end) {
            // Malformed IPv4 packet: safest is to PASS
            return XDP_PASS;
        }

        // If the L4 protocol is ICMP (1), drop it
        if (ip->protocol == IPPROTO_ICMP) {
            bpf_printk("XDP_DROP_ICMP: Dropped ICMPv4 from %pI4\n", &ip->saddr);
            return XDP_DROP;
        }
    }

    // Not IPv4-ICMP: allow
    return XDP_PASS;
}
char_license[] SEC("license") = "GPL";
