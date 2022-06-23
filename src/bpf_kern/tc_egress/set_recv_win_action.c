#include "common.h"
#include "utils.h"
#include "error.h"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_ACTION_NUM);
} tc_egress_actions SEC(".maps");

#else

BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM, TC_EGRESS_ACTIONS_PATH);

#endif

#ifdef NOBCC
SEC("tc")
#endif 
int set_recv_win_action(struct __sk_buff *ctx) {
    int res;
    
    TC_POLICY_PRE_SEC

    tc_action_t *a = (tc_action_t*)(&POLICY);

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

    TC_ACTION_POST_SEC
 
next_action:                          

#ifdef NOBCC
    bpf_tail_call(ctx, &tc_egress_actions, NEXT_IDX);
#else
    tc_egress_actions.call(ctx, NEXT_IDX);
#endif 
    res = -TAIL_CALL_FAIL;                      
    goto fail;

out_of_bound:
fail: 
    return TC_ACT_UNSPEC;

exit:
    //bpf_trace_printk("finish!");
    return TC_ACT_UNSPEC;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
