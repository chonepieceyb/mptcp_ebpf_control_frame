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

struct flow_prio_param_t {
    __u8       B:1,     //if B == 1 use flow as a backup 
               A:1,     //if A == 1 provide address id 
               rsv:6;
    __u8       address_id;
};

#ifdef NOBCC
SEC("tc")
#endif 
int set_flow_priority_action(struct __sk_buff *ctx) {
    int res;
    int modified = 0;
    
    TC_POLICY_PRE_SEC

    tc_action_t *a = (tc_action_t *)(&POLICY);

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
    res = tc_grow_tcp_header(ctx, &nh, tcp_opt_len, sizeof(struct mp_prio), &modified);  //nh.pos set to the end 
    if (res < 0) {
        res = -TC_GROW_TCP_HEADER_FAIL;
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
