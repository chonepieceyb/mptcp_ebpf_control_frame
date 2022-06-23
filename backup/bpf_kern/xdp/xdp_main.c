#include "common.h"

BPF_TABLE_PINNED("prog", int, int, xdp_actions, 1024, "/sys/fs/bpf/xdp_actions");
BPF_TABLE_PINNED("hash", struct tcp_4_tuple, struct subflow, subflows, 200000, "/sys/fs/bpf/tc/globals/subflows");

int xdp_main(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int res;
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res <= 20) {
        goto not_target;
    }
    
    struct tcp_4_tuple flow_key;
    struct subflow *sub;
    __builtin_memset(&flow_key, 0, sizeof(struct tcp_4_tuple));
    __builtin_memset(&sub, 0, sizeof(struct subflow));

    //交换一下
    flow_key.local_addr = iph->daddr;
    flow_key.peer_addr = iph->saddr;
    flow_key.local_port = tcph->dest;
    flow_key.peer_port = tcph->source;
    
    sub = subflows.lookup(&flow_key);
    if (sub == NULL) goto not_target;

    int flow_action;
    flow_action = sub->action;
    
    if (flow_action < 0) goto default_action;

    xdp_actions.call(ctx, flow_action);   
fail:
    return action;

not_target:
    return action;

default_action:
    bpf_trace_printk("xdp flow with default action\n");
    return action;
}
