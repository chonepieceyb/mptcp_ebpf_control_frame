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

#ifdef DEBUG
DEBUG_DATA_DEF_SEC
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_XDP_EMPTCP_EVENTS_SIZE);
} xdp_eMPTCP_events SEC(".maps");

#else

BPF_TABLE_PINNED("prog", int, int, xdp_actions, MAX_XDP_ACTION_NUM, XDP_ACTIONS_PATH);

#endif

#define ADD_ADDR_OPT_BASE 16      //without port 
#define ADD_ADDR_OPT_PORT 18     //with port
#define MAX_ADD_ADDR_OPT_LEN  18    // ipv4

struct rm_add_addr_event_t {
    eMPTCP_event_header_t header;
    struct tcp4tuple flow;
    __u32 opt_len;
    char add_addr_opt[MAX_ADD_ADDR_OPT_LEN];
};

static __always_inline int send_rm_addr_event(struct xdp_md *ctx, void *data_end, const struct iphdr *iph, const struct tcphdr *tcph, const struct mptcp_option *opt) {
    int res;
    struct rm_add_addr_event_t e;
    __builtin_memset(&e, 0, sizeof(e));
    e.header.event = MP_RM_ADD_ADDR;
    e.header.time_ns = bpf_ktime_get_ns();
    e.header.len = sizeof(e);
    get_tcp4tuple_in(iph, tcph, &e.flow);
    e.opt_len = opt->len;
    
    if (opt->len == ADD_ADDR_OPT_BASE) {
        CHECK_BOUND_BY_SIZE(opt, data_end, ADD_ADDR_OPT_BASE);
        __builtin_memcpy(&e.add_addr_opt, opt, ADD_ADDR_OPT_BASE);
    } else if (opt->len == ADD_ADDR_OPT_PORT) {
        CHECK_BOUND_BY_SIZE(opt, data_end, ADD_ADDR_OPT_PORT);
        __builtin_memcpy(&e.add_addr_opt, opt, ADD_ADDR_OPT_PORT);
    } else if (opt->len == 8) {
        //V0 without port
        CHECK_BOUND_BY_SIZE(opt, data_end, 8);
        __builtin_memcpy(&e.add_addr_opt, opt, 8);
    }
    else {
        goto fail;
    }
 
    res = bpf_perf_event_output(ctx, &xdp_eMPTCP_events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    bpfprintk("perf event output end %d\n", res); 
    if (res < 0) goto fail;
    return 0;
    //send event 
fail:
out_of_bound:
    return -SUBMIT_EVENT_FAIL;
}

#ifdef NOBCC
SEC("xdp")
#endif 
int rm_add_addr_action(struct xdp_md *ctx) {
    #ifdef DEBUG
    INIT_DEBUG_EVENT(RM_ADD_ADDR)

    RECORD_DEBUG_EVENTS(start)
    #endif


    int res;
    int modified = 0;
    
    XDP_POLICY_PRE_SEC
    
    //rm add addr without param 
    
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res < 0) {
        res = -NOT_TCP;
        goto fail;
    }
    
    //only work on tcp ack 
    if (!(tcph->ack && !tcph->syn)) {
        goto next;
    }
    
    //get addr option
    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_ADD_ADDR);
    if (res < 0) {
        goto next;
    }
    struct mptcp_option *mptcp_opt = nh.pos;
    CHECK_BOUND(mptcp_opt, data_end);

    if (mptcp_opt->len > MAX_ADD_ADDR_OPT_LEN) {
        goto next;
    }
    
    //send event to userspace for recover 
    res = send_rm_addr_event(ctx, data_end, iph, tcph, mptcp_opt);

    bpfprintk("send rm add addr event end res: %d\n", res);

    return XDP_DROP;

/*
    res = rm_tcp_header(&nh, data_end, tcph, mptcp_opt->len, &modified);

    //bpfprintk("rm add addr end res: %d\n", res);
    if (res < 0) {
        goto fail;
    }
*/    
    XDP_ACTION_POST_SEC

next_action:                          
    #ifdef DEBUG
    RECORD_DEBUG_EVENTS(end)
    SEND_DEBUG_EVENTS
    #endif

#ifdef NOBCC
    bpf_tail_call(ctx, &xdp_actions, NEXT_IDX);
#else
    xdp_actions.call(ctx, NEXT_IDX);
#endif 
    res = -TAIL_CALL_FAIL;                      
    goto fail;

out_of_bound:
fail:
    if (modified) {
        return XDP_DROP;
    } else {
        return XDP_PASS;
    }
exit:
    #ifdef DEBUG
    RECORD_DEBUG_EVENTS(end)
    SEND_DEBUG_EVENTS
    #endif

    return XDP_PASS;

}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
