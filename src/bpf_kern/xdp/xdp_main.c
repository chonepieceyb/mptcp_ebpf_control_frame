#include "common.h"
#include "error.h"
#include "utils.h"
#include "actions_def.h"

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
    __type(value, xdp_subflow_action_t);
    __uint(max_entries, MAX_SUBFLOW_NUM);
} subflow_action_ingress SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, xdp_action_flag_key_t);
    __type(value, xdp_action_flag_t);;
    __uint(max_entries, XDP_ACTIONS_FLAG_SIZE);
} xdp_actions_flag SEC(".maps");

#else
BPF_TABLE_PINNED("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM,  XDP_ACTIONS_PATH);
BPF_TABLE_PINNED("hash", flow_key_t, xdp_subflow_action_t, subflow_action_ingress, MAX_SUBFLOW_NUM, SUBFLOW_ACTION_INGRESS_PATH);
BPF_TABLE_PINNED("hash", xdp_action_flag_key_t, xdp_action_flag_t, xdp_actions_flag, XDP_ACTIONS_FLAG_SIZE, XDP_ACTIONS_FLAG_PATH);
#endif

//return 0 if action chain not need changed 
/*SUBFLOW_MAX_ACTION_NUM
 * @param : actions: actions get from xdp_subflow_actions 
 * *          new_actions: new actions (if return 0, new_actions == actions(before call func), new action should be set to zero before call this func
 *          action_num: action num to be set 
 */
static __always_inline int parse_xdp_action_chain(const xdp_action_t actions[SUBFLOW_MAX_ACTION_NUM], xdp_action_t new_actions[SUBFLOW_MAX_ACTION_NUM], xdp_action_flag_key_t *flag_key,  __u8 *action_num) {
    int res = 0; 
    *action_num = 0;
    void *val = NULL;
    xdp_action_t *new_action = new_actions;
    #pragma unroll 
    for (int i = 0; i < SUBFLOW_MAX_ACTION_NUM; i++) {
        int action = actions[i].u1.action;
        if (action == DEFAULT_ACTION) break;
        
        int need_meta = xdp_action_need_meta(action);
        if (need_meta) {
            __builtin_memcpy(&(flag_key->action), &(actions[i]), sizeof(xdp_action_t));
#ifdef NOBCC
            val = bpf_map_lookup_elem(&xdp_actions_flag, flag_key);
#else
            val = xdp_actions_flag.lookup(flag_key);     
#endif 
            if (val == NULL) {
                //flag had been deleted 
                //also means that action need to be delete 
                res = -1;
                continue;
            }
        }
        __builtin_memcpy(new_action++, &(actions[i]), sizeof(xdp_action_t));;
    }
    *action_num = new_action - new_actions;
    return res;
}

// return 0 if success else return -1 
static __always_inline int set_xdp_action_chain(struct xdp_md *ctx, xdp_action_t actions[SUBFLOW_MAX_ACTION_NUM], __u8 action_num, __u8 *first_action) {
    //遍历几个字节的事情，我觉得开销应该不会特别大
    long res;

    //一个action都没有
    if (action_num == 0) {
        *first_action = 0;
        return 0;
    }
    
    *first_action = actions[0].u1.action;
    #pragma unroll 
    for (int i = 0; i < SUBFLOW_MAX_ACTION_NUM-1; i++) {
        actions[i].u1.next_action = actions[i+1].u1.action;
    }
    actions[SUBFLOW_MAX_ACTION_NUM-1].u1.next_action = DEFAULT_ACTION;
    
    //adjust xdp_meta and set action chain to xdp_meta 
    res = bpf_xdp_adjust_meta(ctx, -(action_num * sizeof(xdp_action_t)));
    if (res < 0) {
        return -FAILED_ADJUST_XDP_META;
    }
    
    void *data = (void *)(__u64)(ctx->data);
    void *pos = (void *)(__u64)(ctx->data_meta);
    void *action = actions;

    #pragma unroll SUBFLOW_MAX_ACTION_NUM
    for (int i = 0; i < SUBFLOW_MAX_ACTION_NUM; i++) {
        if (i >= action_num) break;
        if (pos + sizeof(xdp_action_t) > data) {
            return -FAILED_ADJUST_XDP_META;
        }
        __builtin_memcpy(pos, action, sizeof(xdp_action_t));
        pos += sizeof(xdp_action_t);
        action += sizeof(xdp_action_t);
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
    
    xdp_action_flag_key_t flag_key;
    xdp_subflow_action_t *sub_actions;
    xdp_action_t actions[SUBFLOW_MAX_ACTION_NUM];
    xdp_action_t new_actions[SUBFLOW_MAX_ACTION_NUM];

    __builtin_memset(&flag_key, 0, sizeof(xdp_action_flag_key_t));
    __builtin_memset(actions, 0, sizeof(actions));
    __builtin_memset(new_actions, 0, sizeof(new_actions));

    get_ingress_flow_key(iph, tcph, &(flag_key.flow));

#ifdef NOBCC
    sub_actions = bpf_map_lookup_elem(&subflow_action_ingress, &(flag_key.flow));
#else
    sub_actions = subflow_action_ingress.lookup(&(flag_key.flow));
#endif
    if (sub_actions == NULL) goto not_target;

    __builtin_memcpy(&actions, &sub_actions->actions, sizeof(xdp_action_t) * SUBFLOW_MAX_ACTION_NUM);
    //parse action 
    __u8 action_num;
    __u8 first_action;
    res = parse_xdp_action_chain(actions, new_actions, &flag_key, &action_num);


    //update subflow action 
    if (res != 0) {
        __builtin_memcpy(&sub_actions->actions, new_actions, sizeof(xdp_action_t) * SUBFLOW_MAX_ACTION_NUM);
    }

    //set action
    res = set_xdp_action_chain(ctx, new_actions, action_num, &first_action);
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
    res = XDP_TAIL_CALL_FAIL;

fail:
    return XDP_PASS;

not_target:
    return XDP_PASS;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
