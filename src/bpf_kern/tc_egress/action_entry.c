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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, action_chain_id_t);
    __type(value, tc_action_chain_t);
    __uint(max_entries, MAX_TC_EGRESS_ACTION_CHAIN_NUM);
} tc_egress_action_chains SEC(".maps");

#else
BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM,  TC_EGRESS_ACTIONS_PATH);
BPF_TABLE_PINNED("hash", action_chain_id_t, tc_action_chain_t, tc_egress_action_chains, MAX_TC_EGRESS_ACTION_CHAIN_NUM, TC_EGRESS_ACTION_CHAINS_PATH);
#endif

#ifdef NOBCC
SEC("tc")
#endif 
int action_entry(struct __sk_buff *ctx) {
    int res;
    action_chain_id_t chain_key;
    
    tc_get_action_chain_id(ctx, &chain_key);
    
    tc_policy_t policies[MAX_POLICY_LEN];
    __builtin_memset(&policies, 0, sizeof(policies));

    __u8 first_policy = DEFAULT_POLICY;
    tc_action_chain_t *chain;

#ifdef NOBCC
    chain = bpf_map_lookup_elem(&tc_egress_action_chains, &chain_key);
#else
    chain = tc_egress_action_chains.lookup(&chain_key);
#endif

    if (chain == NULL) {
        res = TC_E_ACTION_CHAIN_ID_NOTFOUND;
        goto fail;
    }

    //copied for concurrency 
    __builtin_memcpy(&policies, &chain->actions, MAX_POLICY_LEN * sizeof(tc_policy_t));
    
    //set selector chain
    tc_set_policy_chain(ctx, policies, &first_policy);
    if (first_policy == DEFAULT_POLICY) {
        goto not_target;
    }
        
#ifdef NOBCC
    bpf_tail_call(ctx, &tc_egress_actions, first_policy);
#else
    tc_egress_actions.call(ctx, first_policy);
#endif
    res = TAIL_CALL_FAIL;
    goto fail;

fail:
    return TC_ACT_UNSPEC;

not_target:
    return TC_ACT_UNSPEC;

}

#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
