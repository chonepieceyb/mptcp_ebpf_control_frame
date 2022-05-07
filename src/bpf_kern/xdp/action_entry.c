#include "common.h"
#include "error.h"
#include "utils.h"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_ACTION_NUM);
} xdp_actions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, action_chain_id_t);
    __type(value, xdp_action_chain_t);
    __uint(max_entries, MAX_XDP_ACTION_CHAIN_NUM);
} xdp_action_chains SEC(".maps");

#else
BPF_TABLE_PINNED("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM,  XDP_ACTIONS_PATH);
BPF_TABLE_PINNED("hash", action_chain_id_t, xdp_action_chain_t, xdp_action_chains, MAX_XDP_ACTION_CHAIN_NUM, XDP_ACTION_CHAINS_PATH);
#endif

#ifdef NOBCC
SEC("xdp")
#endif 
int action_entry(struct xdp_md *ctx)
{
    int res;
    action_chain_id_t chain_key;
    
    res = xdp_get_action_chain_id(ctx, &chain_key);
    if (res < 0) {
        goto fail;
    }

    xdp_policy_t policies[MAX_POLICY_LEN];
    __builtin_memset(&policies, 0, sizeof(policies));

    __u8 first_policy = DEFAULT_POLICY;
    xdp_action_chain_t *chain;

#ifdef NOBCC
    chain = bpf_map_lookup_elem(&xdp_action_chains, &chain_key);
#else
    chain = xdp_action_chains.lookup(&chain_key);
#endif

    if (chain == NULL) {
        res = XDP_ACTION_CHAIN_ID_NOTFOUND;
        goto fail;
    }

    //copied for concurrency 
    __builtin_memcpy(&policies, &chain->actions, MAX_POLICY_LEN * sizeof(xdp_policy_t));
    
    //set selector chain
    res = xdp_set_policy_chain(ctx, policies, &first_policy);
    if (res < 0) {
        goto fail;
    }

    if (first_policy == DEFAULT_POLICY) {
        goto not_target;
    }
        
#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_actions, first_policy);
#else
    xdp_actions.call(ctx, first_policy);
#endif
    res = TAIL_CALL_FAIL;
    goto fail;

fail:
    return XDP_PASS;

not_target:
    return XDP_PASS;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
