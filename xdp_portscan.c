#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SCAN_THRESHOLD 20

// Define an LRU Hash Map to track Source IPs and their scan counts
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Source IP address
    __type(value, __u32); // Number of SYN packets sent
} scan_map SEC(".maps");

SEC("xdp")
int xdp_portscan_detector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parse IP Header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 3. Parse TCP Header
    // The IP header length is variable, so we calculate it
    struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // 4. Port Scan Logic (Check for SYN packets)
    if (tcph->syn && !tcph->ack) {
        __u32 src_ip = iph->saddr;
        __u32 *count;
        __u32 init_count = 1;

        // Lookup the IP in our LRU map
        count = bpf_map_lookup_elem(&scan_map, &src_ip);
        if (count) {
            // If they are over the threshold, drop the packet (Active Defense)
            if (*count >= SCAN_THRESHOLD) {
                // You can uncomment the line below to log to /sys/kernel/debug/tracing/trace_pipe
                // bpf_printk("Scan blocked from IP: %x\n", src_ip);
                return XDP_DROP;
            }
            // Increment their count
            __sync_fetch_and_add(count, 1);
        } else {
            // First time seeing this IP send a SYN, add to map
            bpf_map_update_elem(&scan_map, &src_ip, &init_count, BPF_ANY);
        }
    }

    return XDP_PASS; // Allow normal traffic
}

char _license[] SEC("license") = "GPL";
