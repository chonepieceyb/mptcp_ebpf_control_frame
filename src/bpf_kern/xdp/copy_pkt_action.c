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

#endif

struct copy_pkt_param_t {
    __u16 event;
};

#ifdef NOBCC
SEC("xdp")
#endif 
int copy_pkt_action(struct xdp_md *ctx) {
    #ifdef DEBUG
    INIT_DEBUG_EVENT(COPY_PKT)
    RECORD_DEBUG_EVENTS(start)
    #endif

    int res;
    int modified = 0;
    
    XDP_POLICY_PRE_SEC
    
    xdp_action_t *a = (xdp_action_t *)(&POLICY);

    //get param
    struct copy_pkt_param_t *copy_param; 
    if (a->param_type != IMME) {
        res = -INVALID_ACTION_ARGUMENT;
        goto fail;
    }

    copy_param = (struct copy_pkt_param_t *)(&a->param.imme);

    //rm add addr without param 
    
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    //bpfprintk("data len, %u", (int)(data_end - data));
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

    //find dss option 
    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_DSS);
    if (res < 0) {
        goto next;
    }
    struct mp_dss *dss = nh.pos;
    CHECK_BOUND(dss, data_end);

    // send event 
    mptcp_copy_pkt_event e;
    __builtin_memset(&e, 0, sizeof(mptcp_copy_pkt_event));
    e.header.event = copy_param->event;
    res = pre_copy_mptcp_pkt(data_end, eth, iph, tcph, dss, &e);

    if (res < 0) {
        res = -PRE_COPY_PKT_FAIL;
        goto fail;
    }
    
    res = bpf_perf_event_output(ctx, &xdp_eMPTCP_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    if (res < 0) {
        res = -SUBMIT_EVENT_FAIL;
        goto fail;
    }

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
