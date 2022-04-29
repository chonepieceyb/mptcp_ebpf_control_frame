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
int rm_add_addr_ingress(struct xdp_md *ctx) {
    int res;
/*
 **************action opt begin*************
 */
    //get action 
    xdp_action_t a;   //4bytes 
    res = get_and_pop_xdp_action(ctx, &a);
    if (res < 0) {
        goto fail_no_modify;
    }
    __u8 next_action = a.u1.next_action;
/*
 * ************action opt end***************
 */

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
        res = -INTERNAL_IMPOSSIBLE;
        goto fail_no_modify;
    }
    
    //only work on tcp ack 
    if (!(tcph->ack && !tcph->syn)) {
        goto next_action;
    }
    
    //get addr option
    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_ADD_ADDR);
    if (res < 0) {
        goto next_action;  //not our target 
    }
    struct mptcp_option *mptcp_opt = nh.pos;
    CHECK_BOUND(mptcp_opt, data_end);

    res =  xdp_rm_tcp_header(&nh, data_end, tcph, mptcp_opt->len);

    if (res == -2) goto fail_modify;

next_action:
    if (next_action == DEFAULT_ACTION) {
        goto finish;
    }

    //call next action
#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_actions, next_action);
#else
    xdp_actions.call(ctx, next_action);
#endif
    res = XDP_TAIL_CALL_FAIL;

fail_modify:
    return XDP_DROP;

fail_no_modify: 
    return XDP_PASS;

finish:
    return XDP_PASS;

out_of_bound:
    return XDP_PASS;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
