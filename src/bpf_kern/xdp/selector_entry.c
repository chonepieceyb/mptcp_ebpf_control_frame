#include "common.h"
#include "error.h"
#include "utils.h"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_SELECTOR_NUM);
} xdp_selectors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, xdp_selector_chain_t);
    __uint(max_entries, 1);
} xdp_selector_chain SEC(".maps");

#ifdef DEBUG
DEBUG_DATA_DEF_SEC
#endif

#else
BPF_TABLE_PINNED("prog", int, int, xdp_selectors, MAX_XDP_SELECTOR_NUM,  XDP_SELECTORS_PATH);
BPF_TABLE_PINNED("array", int, xdp_selector_chain_t, xdp_selector_chain, 1, XDP_SELECTOR_CHAIN_PATH);
#endif

#ifdef NOBCC
SEC("xdp")
#endif 
int selector_entry(struct xdp_md *ctx)
{
    #ifdef DEBUG
    INIT_DEBUG_EVENT(SEL_ENTRY)

    RECORD_DEBUG_EVENTS(start)
    #endif

    //get selector chain 
    int res;
    int chain_key = 0;
    xdp_selector_chain_t *chain;

    xdp_policy_t policies[MAX_POLICY_LEN];
    __builtin_memset(&policies, 0, sizeof(policies));

    __u8 first_policy = DEFAULT_POLICY;

#ifdef NOBCC
    chain = bpf_map_lookup_elem(&xdp_selector_chain, &chain_key);
#else
    chain = xdp_selector_chain.lookup(&chain_key);
#endif

    //no chain configed do nothing 
    if (chain == NULL) goto not_target;

    //copied for concurrency 
    __builtin_memcpy(&policies, &chain->selectors, MAX_POLICY_LEN * sizeof(xdp_policy_t));
    
    //set selector chain
    res = xdp_set_policy_chain(ctx, policies, &first_policy);
    if (res < 0) {
        goto fail;
    }

    if (first_policy == DEFAULT_POLICY) {
        goto not_target;
    }
    
#ifdef DEBUG
    RECORD_DEBUG_EVENTS(end)
    SEND_DEBUG_EVENTS
#endif

#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_selectors, first_policy);
#else
    xdp_selectors.call(ctx, first_policy);
#endif
    res = -TAIL_CALL_FAIL;

fail:
    return XDP_PASS;

not_target:
    return XDP_PASS;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
