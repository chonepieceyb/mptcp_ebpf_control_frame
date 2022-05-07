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

#endif

#ifdef NOBCC
SEC("xdp")
#endif 
int rm_add_addr_action(struct xdp_md *ctx) {
    int res;
    int modified = 0;
    
    XDP_POLICY_PRE_SEC
    
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

    res =  xdp_rm_tcp_header(&nh, data_end, tcph, mptcp_opt->len, &modified);

    if (res < 0) {
        goto fail;
    }
    
    XDP_ACTION_POST_SEC

#ifndef NOBCC
next_action:                          
    xdp_actions.call(ctx, NEXT_IDX);
    res = -TAIL_CALL_FAIL;                      
    goto fail;
#endif 

out_of_bound:
fail:
    if (modified) {
        return XDP_DROP;
    } else {
        return XDP_PASS;
    }
exit:
    return XDP_PASS;

}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
