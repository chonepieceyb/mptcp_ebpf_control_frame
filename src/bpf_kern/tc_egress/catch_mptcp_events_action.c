#include "common.h"
#include "utils.h"
#include "error.h"
#include "events_def.h"

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_ACTION_NUM);
} tc_egress_actions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_EMPTCP_EVENTS_SIZE);
} tc_egress_eMPTCP_events SEC(".maps");

#else

BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM, TC_EGRESS_ACTIONS_PATH);

#define TC_EGRESS_EMPTCP_EVENTS_SEC  "maps/perf_output:"TC_EGRESS_EMPTCP_EVENTS_PATH

struct tc_egress_eMPTCP_events_table_t { 
  int key; 
  u32 leaf; 
  /* map.perf_submit(ctx, data, data_size) */ 
  int (*perf_submit) (void *, void *, u32); 
  int (*perf_submit_skb) (void *, u32, void *, u32); 
  u32 max_entries; 
}; 
__attribute__((section(TC_EGRESS_EMPTCP_EVENTS_SEC))) 
struct tc_egress_eMPTCP_events_table_t tc_egress_eMPTCP_events = { .max_entries = MAX_TC_EGRESS_EMPTCP_EVENTS_SIZE};

#endif

struct fin_event_t {
    eMPTCP_event_header_t header;
    struct tcp4tuple flow;
};

struct mp_capable_event_t {
    eMPTCP_event_header_t header; 
    struct tcp4tuple flow;
    __u64  local_key;
    __u64  remote_key;
};

struct mp_join_event_t {
    eMPTCP_event_header_t header;
    struct tcp4tuple flow;
    __u32  token;
};

static __always_inline int send_fin_event(struct __sk_buff *ctx, const struct iphdr *iph, const struct tcphdr *tcph ) {
    int res;
    struct fin_event_t fe; 
    __builtin_memset(&fe, 0, sizeof(struct fin_event_t));
    fe.header.event = FIN_EVENT;
    fe.header.len = sizeof(struct fin_event_t);
    get_tcp4tuple_out(iph, tcph, &fe.flow);
    fe.header.time_ns = bpf_ktime_get_ns();
#ifdef NOBCC
    res = bpf_perf_event_output(ctx, &tc_egress_eMPTCP_events, BPF_F_CURRENT_CPU, &fe, sizeof(struct fin_event_t));
#else
    res = tc_egress_eMPTCP_events.perf_submit(ctx, &fe, sizeof(struct fin_event_t));
#endif
    if (res < 0) {
        return -SUBMIT_EVENT_FAIL;
    }
    return 0;
}

static __always_inline int send_mpcapble_event(struct __sk_buff *ctx, const struct iphdr *iph, const struct tcphdr *tcph, const struct mp_capable *mpc) {
    int res;
    struct mp_capable_event_t mpce; 
    __builtin_memset(&mpce, 0, sizeof(struct mp_capable_event_t));
    mpce.header.event = MP_CAPABLE_EVENT;
    mpce.header.len = sizeof(struct mp_capable_event_t);
    get_tcp4tuple_out(iph, tcph, &mpce.flow);
    mpce.local_key = mpc->sender_key;
    mpce.remote_key = mpc->receiver_key;
    mpce.header.time_ns = bpf_ktime_get_ns();

    #ifdef NOBCC
    res = bpf_perf_event_output(ctx, &tc_egress_eMPTCP_events, BPF_F_CURRENT_CPU, &mpce, sizeof(struct mp_capable_event_t));
#else
    res = tc_egress_eMPTCP_events.perf_submit(ctx, &mpce, sizeof(struct mp_capable_event_t));
#endif
    if (res < 0) {
        return -SUBMIT_EVENT_FAIL;
    }
    return 0;
}

static __always_inline int send_mpjoin_event(struct __sk_buff *ctx, const struct iphdr *iph, const struct tcphdr *tcph, const struct mp_join *mpj) {
    int res;
    struct mp_join_event_t mpje; 
    __builtin_memset(&mpje, 0, sizeof(struct mp_join_event_t));
    mpje.header.event = MP_JOIN_EVENT;
    mpje.header.len = sizeof(struct mp_join_event_t);
    get_tcp4tuple_out(iph, tcph, &mpje.flow);
    mpje.token = mpj->u.syn.token;
    mpje.header.time_ns = bpf_ktime_get_ns();

#ifdef NOBCC
    res = bpf_perf_event_output(ctx, &tc_egress_eMPTCP_events, BPF_F_CURRENT_CPU, &mpje, sizeof(struct mp_join_event_t));
#else
    res = tc_egress_eMPTCP_events.perf_submit(ctx, &mpje, sizeof(struct mp_join_event_t));
#endif
    if (res < 0) {
        return -SUBMIT_EVENT_FAIL;
    }
    return 0;
}

#ifdef NOBCC
SEC("tc")
#endif 
int catch_mptcp_events_action(struct __sk_buff *ctx) {
    int res;
    
    TC_POLICY_PRE_SEC

    tc_action_t *a = (tc_action_t*)(&POLICY);

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
    
    /*
     * 1. catch 3th MP_CAPABLE hand-shake packet
     * 2. catch 1st MP_JOIN 
     * 3. catch fin signal
     */
    
    if (tcph->fin || tcph->rst) {
        res = send_fin_event(ctx, iph, tcph);
        goto send_event_finish;
    }
    
    __u32 mp_opt_flags = 0;
    mp_opt_flags |= MPTCP_SUB_CAPABLE_FLAG;
    mp_opt_flags |= MPTCP_SUB_JOIN_FLAG;
    res = check_mptcp_opts(&nh, data_end, tcphl - 20, mp_opt_flags);
    if (res < 0) {
        res = -CHECK_MPTCP_OPTS_FAIL;
        goto fail;
    }
    if (res == 1) {
        //not found
        goto next_action;
    }
    struct mptcp_option *opt = (struct mptcp_option*)(nh.pos);
    CHECK_BOUND(opt,data_end);
    //len == 1
    if ((!tcph->syn) && opt->sub == MPTCP_SUB_CAPABLE) {
        struct mp_capable *mpc = (struct mp_capable*)(opt);
        CHECK_BOUND(mpc, data_end);       
        res = send_mpcapble_event(ctx, iph, tcph, mpc);
        goto send_event_finish;
    } else if ((opt->sub == MPTCP_SUB_JOIN) && tcph->syn && (!tcph->ack)) {
        struct mp_join *mpj = (struct mp_join*)(opt);
        CHECK_BOUND_BY_SIZE(mpj, data_end, offsetof(struct mp_join, u.syn.nonce));
        res = send_mpjoin_event(ctx,iph, tcph, mpj);
        goto send_event_finish;
    } else {
        //not target
        goto next_action;
    }

    TC_ACTION_POST_SEC

send_event_finish:
    if (res < 0) {
        goto fail;
    }
next_action:                          

#ifdef NOBCC
    bpf_tail_call(ctx, &tc_egress_actions, NEXT_IDX);
#else
    tc_egress_actions.call(ctx, NEXT_IDX);
#endif 
    res = -TAIL_CALL_FAIL;                      
    goto fail;

out_of_bound:
fail: 
    return TC_ACT_UNSPEC;

exit:
    return TC_ACT_UNSPEC;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
