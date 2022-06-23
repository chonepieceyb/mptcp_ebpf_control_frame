#include "common.h"
#include "error.h"

struct bpf_elf_map __section("maps") tc_egress_tailcall = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .size_key = sizeof(int),
    .size_value = sizeof(int),
    .max_elem = 4,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map __section("maps") subflows = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct tcp_4_tuple),
    .size_value = sizeof(struct subflow),
    .max_elem = 200000,
    .pinning = PIN_GLOBAL_NS
};


struct bpf_elf_map __section("maps") mptcp_connects = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct mptcp_connect),
    .max_elem = 100000,
    .pinning = PIN_GLOBAL_NS
};
/*
 * return 0 : success 
 * return -NOT_TARGET: not target 
 */
static __always_inline int record_flow_info(const struct iphdr *iph, const struct tcphdr *tcph) {
    struct tcp_4_tuple flow_key;
    struct subflow *sub;
    __builtin_memset(&flow_key, 0, sizeof(struct tcp_4_tuple));
    
    flow_key.local_addr = iph->saddr;
    flow_key.peer_addr = iph->daddr;
    flow_key.local_port = tcph->source;
    flow_key.peer_port = tcph->dest;
    
    sub = bpf_map_lookup_elem(&subflows, &flow_key);
    
    if (sub == NULL) return -NOT_TARGET;

    int data_len = cal_segment_len(iph, tcph);
    
    //保证了单操作的原子性，但是没有保证 pkts 和 data的一致性。目前我认为不是那么重要
    //如果后面有需要，考虑加锁，目前暂时不加锁
    
    lock_xadd(&sub->sended_pkts, 1);
    lock_xadd(&sub->sended_data, data_len);

    return 0;
}

static __always_inline int delete_flow(const struct iphdr *iph, const struct tcphdr *tcph) {
    struct tcp_4_tuple flow_key;
    struct subflow *sub;
    int res;

    flow_key.local_addr = iph->saddr;
    flow_key.peer_addr = iph->daddr;
    flow_key.local_port = tcph->source;
    flow_key.peer_port = tcph->dest;
    
    sub = bpf_map_lookup_elem(&subflows, &flow_key);
    if (sub == NULL) return -NOT_TARGET;
    
    int address_id = sub->address_id;
    __u32 token = sub->token;

    bpf_map_delete_elem(&subflows, &flow_key);

    if (address_id < 0) {
        res = bpf_map_delete_elem(&mptcp_connects, &token);

        if (res != 0) {
            return -MAINFLOW_DELETE_MP_CONNECT_FAIL;
        }
    }
    
    return 0;
}

__section("classifier") int tc_egress_main(struct __sk_buff *skb) {
    int action = -1;

    void *data = (void *)(__u64)(skb->data);
    void *data_end = (void *)(__u64)(skb->data_end);

    struct hdr_cursor nh = {.pos = data};
    int res;
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res <= 20) {
        goto not_target;
    }

    __u32 mptcp_flags = 0;
    struct mp_capable *mpc = NULL;
    struct mp_join *mpj = NULL;
    struct mp_dss *mpd = NULL;

    if (tcph->fin) {
        bpfprintk("get fin and delete\n");
        res = delete_flow(iph, tcph);
        if (res == 0) goto success;
        if (res == -NOT_TARGET) goto not_target;
        goto fail;
    }

    check_mptcp_opts(&nh, data_end, tcphl - 20, &mptcp_flags);
    
    if (!tcph->syn && (mptcp_flags & MPTCP_SUB_CAPABLE_FLAG)) {
        bpf_tail_call(skb, &tc_egress_tailcall, 0);  // 0 is mpcabable sub
        res = -BPF_TAIL_CALL_FAIL;
        goto fail;
    } 

    //first syn packey of creating subflow
    if ((mptcp_flags & MPTCP_SUB_JOIN_FLAG) && tcph->syn && !tcph->ack) {
        bpf_tail_call(skb, &tc_egress_tailcall, 1);  // 1 is mpcabable join
        res = -BPF_TAIL_CALL_FAIL;
        goto fail;
    }
    
    //normal data packet
    if (mptcp_flags & MPTCP_SUB_DSS_FLAG) {
        res = record_flow_info(iph, tcph);
        if (res == 0) {
            goto success;
        }
    }

not_target:
    return action;

success:
    //record time spent in the future 
    return action;
fail:
    //record debug log in the future 
    bpfprintk("main failed! res: %d\n", res);
    return action;

out_of_bound:
    //record debug log in the future 
    bpfprintk("main out of bound! res: %d\n", res);
    return action;
}

char _license[] SEC("license") = "GPL";
