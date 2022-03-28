#include "common.h"
#include "error.h"

/*
struct bpf_elf_map __section("maps") mp_capable_perf_output = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .size_key = sizeof(int),
    .size_value = sizeof(__u32),
    .max_elem = 10,
    .pinning = PIN_GLOBAL_NS
};
*/
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 10);
} mp_capable_perf_output SEC(".maps");

static __always_inline int send_mpcapble_event(struct __sk_buff *skb, const struct iphdr *iph, const struct tcphdr *tcph, const struct mp_capable *mpc) {
    struct mp_capable_event_t event;
    __builtin_memset(&event, 0, sizeof(event));
    event.connect.local_addr = iph->saddr;
    event.connect.peer_addr = iph->daddr;
    event.connect.local_port = tcph->source;
    event.connect.peer_port = tcph->dest;
    event.sended_data = cal_segment_len(iph, tcph);
    event.peer_key = mpc->receiver_key;
    
    return bpf_perf_event_output(skb, &mp_capable_perf_output, BPF_F_CURRENT_CPU, &event, sizeof(event));
}

SEC("tc")
int tc_egress_mpcapable(struct __sk_buff *skb) {
    int action = -1;

    void *data = (void *)(__u64)(skb->data);
    void *data_end = (void *)(__u64)(skb->data_end);

    struct hdr_cursor nh = {.pos = data};
    int res, tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct mp_capable *mpc;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res <= 20) {
        res = -INTERNEL_IMPOSSIBLE;
        goto fail;
    }

    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_CAPABLE);
    if (res != 0) {
        res = -INTERNEL_IMPOSSIBLE;
        goto fail;
    }
    mpc = (struct mp_capable*)nh.pos;
    CHECK_BOUND(mpc, data_end);
    res = send_mpcapble_event(skb, iph, tcph, mpc);
    if (res != 0) {
        res = -SEND_MPCAPABLE_EVENT_FAIL;
        goto fail;
    }

success:
    //record time spent in the future 
    bpfprintk("mpc success! \n");
    return action;

fail:
    //record debug log in the future 
    bpfprintk("mpc failed! res: %d\n", res);
    return action;

out_of_bound:
    //record debug log in the future 
    bpfprintk("mpc out of bound! res: %d\n", res);
    return action;

}

char _license[] SEC("license") = "GPL";
