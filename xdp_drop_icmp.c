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
    // Raw packet pointers from XDP context
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header safely
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4 packets
    if (eth->h_proto == __bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);

        // Check for truncated IPv4 header
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // Optional: bounds check for IP header length (handling IP options)
        if ((void *)ip + ip->ihl * 4 > data_end)
            return XDP_PASS;

        // Drop ICMP packets (protocol number 1)
        if (ip->protocol == IPPROTO_ICMP) {
            bpf_printk("XDP_DROP_ICMP: Dropped ICMPv4 from %pI4\n", &ip->saddr);
            return XDP_DROP;
        }
    }

    // Not IPv4-ICMP: allow
    return XDP_PASS;
}

// License for eBPF verifier
const char LICENSE[] SEC("license") = "GPL";
