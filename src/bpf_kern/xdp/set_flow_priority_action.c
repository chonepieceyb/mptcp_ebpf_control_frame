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

struct flow_prio_param_t {
    __u8       B:1,     //if B == 1 use flow as a backup 
               A:1,     //if A == 1 provide address id 
               rsv:6;
    __u8       address_id;
};

#ifdef NOBCC
SEC("xdp")
#endif 
int set_flow_priority_action(struct xdp_md *ctx) {
    #ifdef DEBUG
    INIT_DEBUG_EVENT(SET_FLOW_PRIORITY_EVENT)

    RECORD_DEBUG_EVENTS(start)
    #endif

    int res;
    int modified = 0;
    
    XDP_POLICY_PRE_SEC

    xdp_action_t *a = (xdp_action_t *)(&POLICY);

    //get param
    struct flow_prio_param_t *flow_param; 
    if (a->param_type != IMME) {
        res = -INVALID_ACTION_ARGUMENT;
        goto fail;
    }
    flow_param = (struct flow_prio_param_t *)(&a->param.imme);

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

    //only work for data pkt
    if (!(tcph->ack && !tcph->syn)) {
        goto next;
    }

    //build mp_prio opt 
    struct mp_prio prio_opt;
    __builtin_memset(&prio_opt, 0, sizeof(struct mp_prio));
    prio_opt.kind = MPTCP_KIND;
    prio_opt.sub = MPTCP_SUB_PRIO;
    prio_opt.b = flow_param->B;

    if (flow_param->A) {
        //provide address_id 
        prio_opt.len = MPTCP_SUB_LEN_PRIO_ADDR;
        prio_opt.addr_id = flow_param->address_id;
    } else {
        prio_opt.len = MPTCP_SUB_LEN_PRIO;
        set_tcp_nop(&prio_opt.addr_id);
    }

    __u16 tcp_opt_len = tcphl - 20;
    res = xdp_grow_tcp_header(ctx, &nh, tcp_opt_len, sizeof(struct mp_prio), &modified);  //nh.pos set to the end 
    if (res < 0) {
        res = -XDP_GROW_TCP_HEADER_FAIL;
        goto fail;;
    }
    
    data = (void *)(__u64)(ctx->data);
    data_end = (void *)(__u64)(ctx->data_end);

    //get iphdr and tcphdr 
    struct hdr_cursor new_nh;
    new_nh.pos = data;
    res = is_tcp_packet(&new_nh, data_end, &eth, &iph, &tcph);
    if (res < 0) {
        res = -INTERNAL_IMPOSSIBLE;
        goto fail;
    }
    
    //add tcp opts 
    res = add_tcp_opts(&nh, data_end, &prio_opt, sizeof(struct mp_prio));
    modified = 1;
    if (res < 0) {
        res = -XDP_ADD_TCP_OPT_FAIL;
        goto fail;
    }

    //recompute_csum about packet len 
    update_tcphlen_csum(iph, tcph, sizeof(struct mp_prio));
    
    //recompute checksum , mp_prio 4 bytes
    add_tcpopt_csum(&tcph->check, &prio_opt, sizeof(struct mp_prio));
    
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

fail:
    if (modified) {
        return XDP_DROP;
    } else {
        return XDP_PASS;
    }
exit:
    #ifdef DEBUG
    RECORD_DEBUG_EVENTS(end)
    SEND_DEBUG_EVENTS
    #endif

    return XDP_PASS;
}

#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
