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
    __type(key, flow_key_t);
    __type(value, xdp_action_value_t);
    __uint(max_entries, MAX_SUBFLOW_NUM);
} subflow_action_ingress SEC(".maps");

#else
BPF_TABLE_PINNED("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM,  XDP_ACTIONS_PATH);
BPF_TABLE_PINNED("hash", flow_key_t, xdp_action_value_t, subflow_action_ingress, MAX_SUBFLOW_NUM, SUBFLOW_ACTION_INGRESS_PATH);
#endif

// return 0 if success else return -1 
static __always_inline int set_xdp_action_chain(struct xdp_md *ctx, struct action actions[SUBFLOW_MAX_ACTION_NUM], __u8 *first_action) {
    //遍历几个字节的事情，我觉得开销应该不会特别大
    __u16 action_num = 0; 
    long res;

    #pragma unroll
    for (int i = 0; i < SUBFLOW_MAX_ACTION_NUM; i++) {
        if (actions[i].u1.action == DEFAULT_ACTION) break; 
        action_num++;
    }

    //一个action都没有
    if (action_num == 0) {
        *first_action = 0;
        return 0;
    }
    
    *first_action = actions[0].u1.action;
    #pragma unroll 
    for (int i = 0; i < SUBFLOW_MAX_ACTION_NUM-1; i++) {
        actions[i].u1.action = actions[i+1].u1.next_action;
    }
    actions[SUBFLOW_MAX_ACTION_NUM-1].u1.next_action = DEFAULT_ACTION;
    
    //adjust xdp_meta and set action chain to xdp_meta 
    res = bpf_xdp_adjust_meta(ctx, -(action_num * sizeof(struct action)));
    if (res < 0) {
        return -FAILED_ADJUST_XDP_META;
    }
    
    void *data = (void *)(__u64)(ctx->data);
    void *pos = (void *)(__u64)(ctx->data_meta);

    #pragma unroll SUBFLOW_MAX_ACTION_NUM
    for (int i = 0; i < SUBFLOW_MAX_ACTION_NUM; i++) {
        if (i >= action_num) break;
        if (pos + sizeof(struct action) > data) {
            return -FAILED_ADJUST_XDP_META;
        }
        __builtin_memcpy(pos, (void*)actions, sizeof(struct action));
        pos += sizeof(struct action);
    }
    return 0;
}

#ifdef NOBCC
SEC("xdp")
#endif 
int xdp_main(struct xdp_md *ctx)
{
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int res;
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res < 0) {
        goto not_target;
    }
    
    flow_key_t flow_key;
    xdp_action_value_t *sub_actions;
    struct action actions[SUBFLOW_MAX_ACTION_NUM];

    __builtin_memset(&flow_key, 0, sizeof(flow_key_t));
    __builtin_memset(actions, 0, sizeof(actions));

    get_ingress_flow_key(iph, tcph, &flow_key);

#ifdef NOBCC
    sub_actions = bpf_map_lookup_elem(&subflow_action_ingress, &flow_key);
#else
    sub_actions = subflow_action_ingress.lookup(&flow_key);
#endif
    if (sub_actions == NULL) goto not_target;

    __builtin_memcpy(&actions, &sub_actions->actions, sizeof(struct action) * SUBFLOW_MAX_ACTION_NUM);
    //set action
    __u8 first_action = 0;
    res = set_xdp_action_chain(ctx, actions, &first_action);
    if (res < 0) {
        goto fail;
    }
    if (first_action == 0) {
        goto not_target;
    }
    
#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_actions, first_action);
#else
    xdp_actions.call(ctx, first_action);
#endif

fail:
    return XDP_PASS;

not_target:
    return XDP_PASS;
}
