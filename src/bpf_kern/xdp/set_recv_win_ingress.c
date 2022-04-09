#include "common.h"
#include "utils.h"
#include "error.h"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_ACTION_NUM);
} xdp_actions SEC(".maps");

#else
BPF_TABLE_PINNED("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM, XDP_ACTIONS_PATH);
//BPF_TABLE("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM);
#endif

#ifdef NOBCC
SEC("xdp")
#endif 
int set_recv_win_ingress(struct xdp_md *ctx) {
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int res;
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res < 0) {
        res = -INTERNAL_IMPOSSIBLE;
        goto fail;
    }
    
    xdp_action_t a;   //4bytes 
    res = get_xdp_action(ctx, &a);
    if (res < 0) {
        goto fail;
    }

    if (a.param_type != IMME) {
        res = -INVALID_ACTION_ARGUMENT;
        goto fail;
    }

    __be16 window = bpf_htons(a.u2.imme);

    //set window and update checksum;
    csum_replace2(&tcph->check, tcph->window, window); 
    tcph->window = window;

    __u8 next_action = a.u1.next_action;
    if (next_action == DEFAULT_ACTION) {
        goto finish;
    }

    //pop action
    res = pop_xdp_action(ctx);
    if (res < 0) goto fail;

    //call next action
#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_actions, next_action);
#else
    xdp_actions.call(ctx, next_action);
#endif
fail: 
    return XDP_PASS;
finish:
    //bpf_trace_printk("finish!");
    return XDP_PASS;
out_of_bound:
    return XDP_PASS;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
