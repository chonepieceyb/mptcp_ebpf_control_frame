#include "common.h"
#include "error.h"
#include "utils.h"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_SELECTOR_NUM);
} tc_egress_selectors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, tc_selector_chain_t);
    __uint(max_entries, 1);
} tc_egress_selector_chain SEC(".maps");

#else
BPF_TABLE_PINNED("prog", int, int, tc_egress_selectors, MAX_TC_EGRESS_SELECTOR_NUM,  TC_EGRESS_SELECTORS_PATH);
BPF_TABLE_PINNED("array", int, tc_selector_chain_t, tc_egress_selector_chain, 1, TC_EGRESS_SELECTOR_CHAIN_PATH);
#endif

#ifdef NOBCC
SEC("tc")
#endif 
int selector_entry(struct __sk_buff *ctx)
{
    //get selector chain 
    int res;
    int chain_key = 0;
    tc_selector_chain_t *chain;

    tc_policy_t policies[MAX_POLICY_LEN];
    __builtin_memset(&policies, 0, sizeof(policies));

    __u8 first_policy = DEFAULT_POLICY;

#ifdef NOBCC
    chain = bpf_map_lookup_elem(&tc_egress_selector_chain, &chain_key);
#else
    chain = tc_egress_selector_chain.lookup(&chain_key);
#endif

    //no chain configed do nothing 
    if (chain == NULL) goto not_target;

    //copied for concurrency 
    __builtin_memcpy(&policies, &chain->selectors, MAX_POLICY_LEN * sizeof(tc_policy_t));
    
    //set selector chain
    tc_set_policy_chain(ctx, policies, &first_policy);

    if (first_policy == DEFAULT_POLICY) {
        goto not_target;
    }
    
#ifdef NOBCC
    bpf_tail_call(ctx, &tc_egress_selectors, first_policy);
#else
    tc_egress_selectors.call(ctx, first_policy);
#endif
    res = -TAIL_CALL_FAIL;

fail:
    return TC_ACT_UNSPEC;

not_target:
    return TC_ACT_UNSPEC;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif
