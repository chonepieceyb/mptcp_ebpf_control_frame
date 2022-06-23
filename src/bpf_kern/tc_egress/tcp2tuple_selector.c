#include "common.h"
#include "utils.h"
#include "error.h"

#define TC_EGRESS_MAX_TCP2TUPLE_NUM 50000
#define TC_EGRESS_TCP2TUPLE_MAP_PATH "/sys/fs/bpf/eMPTCP/tc_egress_tcp2tuple_map"

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp2tuple);
    __type(value, action_chain_id_t);
    __uint(max_entries, TC_EGRESS_MAX_TCP2TUPLE_NUM);
} tc_egress_tcp2tuple_map SEC(".maps");

#else

BPF_TABLE_PINNED("prog", int, int, tc_egress_selectors, MAX_TC_EGRESS_SELECTOR_NUM, TC_EGRESS_SELECTORS_PATH);

BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM, TC_EGRESS_ACTIONS_PATH);

BPF_TABLE_PINNED("hash", struct tcp2tuple, action_chain_id_t, tc_egress_tcp2tuple_map, TC_EGRESS_MAX_TCP2TUPLE_NUM, TC_EGRESS_TCP2TUPLE_MAP_PATH);

#endif 

#ifdef NOBCC
SEC("tc")
#endif 
int tcp2tuple_selector(struct __sk_buff *ctx) 
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
    
    struct tcp2tuple tcp2t;
    __builtin_memset(&tcp2t, 0, sizeof(struct tcp2tuple));

    action_chain_id_t *ACTION_CHAIN_ID;
    //get tcp2tuple

    get_tcp2tuple_out(iph, &tcp2t);

#ifdef NOBCC
    ACTION_CHAIN_ID = bpf_map_lookup_elem(&tc_egress_tcp2tuple_map, &tcp2t);
#else
    ACTION_CHAIN_ID = tc_egress_tcp2tuple_map.lookup(&tcp2t);
#endif
    
    TC_SELECTOR_POST_SEC

next_selector:                                  
#ifdef NOBCC
    bpf_tail_call(ctx,&tc_egress_selectors, NEXT_IDX);
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

