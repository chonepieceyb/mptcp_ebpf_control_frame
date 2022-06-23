#include "common.h"
#include "utils.h"
#include "error.h"

#define XDP_MAX_TCP4TUPLE_NUM 100000
#define XDP_TCP4TUPLE_MAP_PATH "/sys/fs/bpf/eMPTCP/xdp_tcp4tuple_map"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_SELECTOR_NUM);
} xdp_selectors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_ACTION_NUM);
} xdp_actions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp4tuple);
    __type(value, action_chain_id_t);
    __uint(max_entries, XDP_MAX_TCP4TUPLE_NUM);
} xdp_tcp4tuple_map SEC(".maps");

#ifdef DEBUG
DEBUG_DATA_DEF_SEC
#endif

#else

BPF_TABLE_PINNED("prog", int, int, xdp_selectors, MAX_XDP_SELECTOR_NUM,  XDP_SELECTORS_PATH);

BPF_TABLE_PINNED("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM, XDP_ACTIONS_PATH);

BPF_TABLE_PINNED("hash", struct tcp4tuple, action_chain_id_t, xdp_tcp4tuple_map, XDP_MAX_TCP4TUPLE_NUM, XDP_TCP4TUPLE_MAP_PATH);

#endif 

#ifdef NOBCC
SEC("xdp")
#endif 
int tcp4tuple_selector(struct xdp_md *ctx) {
     #ifdef DEBUG
    INIT_DEBUG_EVENT(TCP4SEL)
    RECORD_DEBUG_EVENTS(start)
    #endif

    int res;

    XDP_SELECTOR_PRE_SEC 

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
    
    struct tcp4tuple tcp4t;
    __builtin_memset(&tcp4t, 0, sizeof(struct tcp4tuple));

    action_chain_id_t *ACTION_CHAIN_ID;
    //get tcp2tuple

    get_tcp4tuple_in(iph, tcph, &tcp4t);

#ifdef NOBCC
    ACTION_CHAIN_ID = bpf_map_lookup_elem(&xdp_tcp4tuple_map, &tcp4t);
#else
    ACTION_CHAIN_ID = xdp_tcp4tuple_map.lookup(&tcp4t);
#endif

    XDP_SELECTOR_POST_SEC

next_selector:                                  
    #ifdef DEBUG
    RECORD_DEBUG_EVENTS(end)
    SEND_DEBUG_EVENTS
    #endif

#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_selectors, NEXT_IDX);
#else
    xdp_selectors.call(ctx, NEXT_IDX);
#endif 
    res = -TAIL_CALL_FAIL;                     
    goto fail;                                 

action_entry:                                  
    #ifdef DEBUG
    RECORD_DEBUG_EVENTS(end)
    SEND_DEBUG_EVENTS
    #endif
#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_actions, XDP_ACTION_ENTRY);
#else
    xdp_actions.call(ctx, XDP_ACTION_ENTRY);
#endif 
    res = -TAIL_CALL_FAIL;                     
    goto fail;                                 

not_target:

    return XDP_PASS;

out_of_bound:
fail: 
    return XDP_PASS;
}

#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif


