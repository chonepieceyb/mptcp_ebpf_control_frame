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
int rm_add_addr_action(struct __sk_buff *ctx) {
    int res;
    int modified = 0;
    
    TC_POLICY_PRE_SEC
    
    //rm add addr without param 
    
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res < 0) {
        res = -NOT_TCP;
        goto fail;
    }
    
    //only work on tcp ack 
    if (!(tcph->ack && !tcph->syn)) {
        goto next;
    }
    
    //get addr option
    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_ADD_ADDR);
    if (res < 0) {
        goto next;
    }
    struct mptcp_option *mptcp_opt = nh.pos;
    CHECK_BOUND(mptcp_opt, data_end);

    res =  rm_tcp_header(&nh, data_end, tcph, mptcp_opt->len, &modified);

    if (res < 0) {
        goto fail;
    }
    
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
    if (modified) {
        return TC_ACT_SHOT;
    } else {
        return TC_ACT_UNSPEC;
    }
exit:
    //bpf_trace_printk("finish!");
    return TC_ACT_UNSPEC;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
