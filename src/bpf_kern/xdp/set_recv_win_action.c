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


#ifdef DEBUG
DEBUG_DATA_DEF_SEC
#endif

#else

BPF_TABLE_PINNED("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM, XDP_ACTIONS_PATH);

#endif

#ifdef NOBCC
SEC("xdp")
#endif 
int set_recv_win_action(struct xdp_md *ctx) {
    #ifdef DEBUG
    INIT_DEBUG_EVENT(SET_RECV_WIN_EVENT)
    RECORD_DEBUG_EVENTS(start)
    #endif

    int res;
    
    XDP_POLICY_PRE_SEC

    xdp_action_t *a = (xdp_action_t *)(&POLICY);

    //get param
    if (a->param_type != IMME) {
        res = -INVALID_ACTION_ARGUMENT;
        goto fail;
    }
    __be16 window = bpf_htons(a->param.imme);

    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    //bpf_trace_printk("finish!");
    if (res < 0) {
        res = -NOT_TCP;
        goto fail;
    }
    
    //set window and update checksum;
    csum_replace2(&tcph->check, tcph->window, window); 
    tcph->window = window;

    XDP_ACTION_POST_SEC
 
next_action:                          
    #ifdef DEBUG
    RECORD_DEBUG_EVENTS(end)
    SEND_DEBUG_EVENTS
    #endif

#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_actions, NEXT_IDX);
#else
    xdp_actions.call(ctx, NEXT_IDX);
#endif 
    res = -TAIL_CALL_FAIL;                      
    goto fail;

out_of_bound:
fail: 
    return XDP_PASS;

exit:
    #ifdef DEBUG
    RECORD_DEBUG_EVENTS(end)
    SEND_DEBUG_EVENTS
    #endif

    //bpf_trace_printk("finish!");
    return XDP_PASS;

}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
