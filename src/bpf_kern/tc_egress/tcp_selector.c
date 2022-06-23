#include "common.h"
#include "utils.h"
#include "error.h"

#define TC_EGRESS_TCP_DEFAULT_ACTION_PATH "sys/fs/bpf/eMPTCP/tc_egress_tcp_default_action"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_SELECTOR_NUM);
} tc_egress_selectors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_ACTION_NUM);
} tc_egress_actions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct default_action_t);
    __uint(max_entries, 1);
} tc_egress_tcp_default_action SEC(".maps");

#else

BPF_TABLE_PINNED("prog", int, int, tc_egress_selectors, MAX_TC_EGRESS_SELECTOR_NUM, TC_EGRESS_SELECTORS_PATH);

BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM, TC_EGRESS_ACTIONS_PATH);

BPF_TABLE_PINNED("array", int, struct default_action_t, tc_egress_tcp_default_action, 1, TC_EGRESS_TCP_DEFAULT_ACTION_PATH);

#endif 

#ifdef NOBCC
SEC("tc")
#endif 
int tcp_selector(struct __sk_buff *ctx) 
{
    int res;

    TC_SELECTOR_PRE_SEC 

    //examine packet 
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res < 0) {
       CHECK_SELECTOR_NOMATCH(SELECTOR_OP);
    }
    
    struct default_action_t *default_action; 
    action_chain_id_t *ACTION_CHAIN_ID;
    int zero_key = 0;

#ifdef NOBCC
    default_action = bpf_map_lookup_elem(&tc_egress_tcp_default_action, &zero_key);
#else
    default_action = tc_egress_tcp_default_action.lookup(&zero_key);
#endif
    if (default_action == NULL || !default_action->enable) {
        ACTION_CHAIN_ID = NULL;
    } else {
        ACTION_CHAIN_ID = &(default_action->id);
    }
    
    TC_SELECTOR_POST_SEC

next_selector:                                  
#ifdef NOBCC
    bpf_tail_call(ctx, &tc_egress_selectors, NEXT_IDX);
#else
    tc_egress_selectors.call(ctx, NEXT_IDX);
#endif 
    res = -TAIL_CALL_FAIL;                     
    goto fail;                                 

action_entry:                                  
#ifdef NOBCC
    bpf_tail_call(ctx, &tc_egress_actions, TC_EGRESS_ACTION_ENTRY);
#else
    tc_egress_actions.call(ctx, TC_EGRESS_ACTION_ENTRY);
#endif 
    res = -TAIL_CALL_FAIL;                     
    goto fail;                                 

not_target:
    return TC_ACT_UNSPEC;

out_of_bound:
fail: 
    return TC_ACT_UNSPEC;
}

#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 

