#include "common.h"
#include "utils.h"
#include "error.h"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_ACTION_NUM);
} xdp_actions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, xdp_action_flag_key_t);
    __type(value, xdp_action_flag_t);;
    __uint(max_entries, XDP_ACTIONS_FLAG_SIZE);
} xdp_actions_flag SEC(".maps");

#else

BPF_TABLE_PINNED("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM, XDP_ACTIONS_PATH);

BPF_TABLE_PINNED("hash", xdp_action_flag_key_t, xdp_action_flag_t, xdp_actions_flag, XDP_ACTIONS_FLAG_SIZE, XDP_ACTIONS_FLAG_PATH);
#endif

struct flow_prio_param_t {
    __u8       B:1,     //if B == 1 use flow as a backup 
               A:1,     //if A == 1 provide address id 
               rsv:6;
    __u8       address_id;
};

#ifdef NOBCC
SEC("xdp")
#endif 
int set_flow_priority_ingress(struct xdp_md *ctx) {
    //bpf_trace_printk("set_flow_priority ingress begin\n");
    int res;

/*
 **************action opt begin*************
 */
    //get action 
    xdp_action_t a;   //4bytes 
    res = get_and_pop_xdp_action(ctx, &a);
    if (res < 0) {
        goto fail_no_modify;
    }
    __u8 next_action = a.u1.next_action;
/*
 * ************action opt end***************
 */

    //get param
    struct flow_prio_param_t *flow_param; 
    if (a.param_type != IMME) {
        res = -INVALID_ACTION_ARGUMENT;
        goto fail_no_modify;;
    }
    flow_param = (struct flow_prio_param_t *)(&a.u2.imme);

    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;


    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res < 0) {
        res = -INTERNAL_IMPOSSIBLE;
        goto fail_no_modify;
    }

//only work for data pkt
    if (!(tcph->ack && !tcph->syn)) {
        goto next_action;
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
    res = xdp_grow_tcp_header(ctx, &nh, tcp_opt_len, sizeof(struct mp_prio));  //nh.pos set to the end 
    if (res == -1) {
        res = -XDP_GROW_TCP_HEADER_FAIL;
        goto fail_no_modify;
    }
    if (res == -2) {
        //res = -XDP_GROW_TCP_HEADER_FAIL;
        goto fail_modify;
    }

    data = (void *)(__u64)(ctx->data);
    data_end = (void *)(__u64)(ctx->data_end);

    //get iphdr and tcphdr 
    struct hdr_cursor new_nh;
    new_nh.pos = data;
    res = is_tcp_packet(&new_nh, data_end, &eth, &iph, &tcph);
    if (res < 0) {
        res = -INTERNAL_IMPOSSIBLE;
        goto fail_modify;   //imposible
    }
    
    //add tcp opts 
    res = add_tcp_opts(&nh, data_end, &prio_opt, sizeof(struct mp_prio));
    if (res < 0) {
        res = -XDP_ADD_TCP_OPT_FAIL;
        goto fail_modify;
    }

    //recompute_csum about packet len 
    update_tcphlen_csum(iph, tcph, sizeof(struct mp_prio));
    
    //recompute checksum , mp_prio 4 bytes
    add_tcpopt_csum(&tcph->check, &prio_opt, sizeof(struct mp_prio));
    
    //delete xdp flag
    xdp_action_flag_key_t flag_key;
    __builtin_memset(&flag_key, 0, sizeof(xdp_action_flag_t));
    
    get_ingress_flow_key(iph, tcph, &(flag_key.flow));

    a.u1.action = SET_FLOW_PRIO_IN_AID;
    __builtin_memcpy(&(flag_key.action), &a, sizeof(xdp_action_t));

    //delete flag 
#ifdef NOBCC
    bpf_map_delete_elem(&xdp_actions_flag, &flag_key);
#else
    xdp_actions_flag.delete(&flag_key);
#endif 

next_action:
    //next call
    if (next_action == DEFAULT_ACTION) {
        goto finish;
    }
#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_actions, next_action);
#else
    xdp_actions.call(ctx, next_action);
#endif
    
    res = -XDP_TAIL_CALL_FAIL;

fail_modify:
   // bpf_trace_printk("set flow prio fail modify, res: %d\n", res);
    return XDP_DROP;

finish:
   // bpf_trace_printk("set flow prio finish , res: %d\n", res);
    return XDP_PASS;

fail_no_modify: 
   // bpf_trace_printk("set flow prio no modify, res: %d\n", res);
    return XDP_PASS;
}

#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
