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

#define XDP_MAX_METRIC_NUM 100000

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct tcp4tuple);
    __type(value, tcp_metrics);
    __uint(max_entries, XDP_MAX_METRIC_NUM);
} xdp_metrics SEC(".maps");

#endif 

#ifdef DEBUG
DEBUG_DATA_DEF_SEC
#endif

struct metric_param_t {
    __u8    pkt:1,
            flow:1,
            rtt:1,
            rsv1:5;
    __u8    rsv2;
};

static __always_inline int create_metric(const struct tcp4tuple *flow) {
    int res; 
    tcp_metrics metric;
    __builtin_memset(&metric, 0, sizeof(metric));
    res = bpf_map_update_elem(&xdp_metrics, flow, &metric, BPF_NOEXIST);
    if (res < 0) {
        res = -UPDATE_METRIC_FAIL;
    }
    return res;
};


#ifdef NOBCC
SEC("xdp")
#endif 
int record_action(struct xdp_md *ctx) {
#ifdef DEBUG
    INIT_DEBUG_EVENT(RECORD)
    RECORD_DEBUG_EVENTS(start)
#endif

    int res;
    //perform per packet record and only record ingress data flow 
    XDP_POLICY_PRE_SEC

    xdp_action_t *a = (xdp_action_t *)(&POLICY);
    
    //get param 
    struct metric_param_t *param;
    if (a->param_type != IMME) {
        res = -INVALID_ACTION_ARGUMENT;
        goto fail;
    }
    param = (struct metric_param_t *)(&a->param.imme);

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
    
    struct tcp4tuple tcp4t;
    tcp_metrics *metrics;
    __builtin_memset(&tcp4t, 0, sizeof(struct tcp4tuple));

    //get tcp4tuple
    get_tcp4tuple_in(iph, tcph, &tcp4t);
    
    metrics = bpf_map_lookup_elem(&xdp_metrics, &tcp4t);

    //if syn create 
    if (tcph->syn) {
        if (metrics != NULL) {
            //first create
            goto next_action;
        }
        res = create_metric(&tcp4t);
        if (res < 0) {
            goto fail;
        }
    }
    
    //if fun delete 
    if (tcph->fin && metrics != NULL) {
        bpf_map_delete_elem(&xdp_metrics, &tcp4t);
    }

    //common ack 
    if (!tcph->ack) goto next_action;
    
    if (metrics == NULL) {
        res = -UPDATE_METRIC_FAIL;
        goto fail;
    }
    //record pkt
    
    if (param->pkt) {
        record_pkt(&metrics->ingress_pkts);
    }
    

    if (param->flow) {
        record_flow_size(&metrics->ingress_flow_size, iph, tcph);
    }

    //get timestamp optionr
    if (param->rtt) {
        res = check_tcp_opt(&nh, data_end, tcphl-20, TCP_TIMESTAMP);
        if (res < 0) {
            goto next_action;
        }
        struct tcp_timestamp_opt *ts_opt = nh.pos;
        CHECK_BOUND(ts_opt, data_end);
        record_rtt(metrics->rtts, &metrics->rtt_producer, ts_opt);
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
    return XDP_PASS;
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


