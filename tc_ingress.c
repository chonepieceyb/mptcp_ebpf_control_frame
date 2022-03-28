#include "common.h"

struct mp_capable_event_t {
    struct tcp_4_tuple connect; 
    __u64 sender_key;
};

//bpf maps define
struct bpf_elf_map __section("maps") mp_capable_perf_output = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .size_key = sizeof(int),
    .size_value = sizeof(__u32),
    .max_elem = 10,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map __section("maps") mptcp_connects = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u64),
    .size_value = sizeof(struct mptcp_connect),
    .max_elem = 100000,
    .pinning = PIN_GLOBAL_NS
};

struct bpf_elf_map __section("maps") subflows = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(struct tcp_4_tuple),
    .size_value = sizeof(struct subflow),
    .max_elem = 200000,
    .pinning = PIN_GLOBAL_NS
};


static __always_inline void record_tcp(const struct tcphdr *tcph, struct subflow *tcp_record) {
    
}

__section("classifier") int tc_ingress_main(struct __sk_buff *skb) {
    int action = -1;

    void *data = (void *)(__u64)(skb->data);
    void *data_end = (void *)(__u64)(skb->data_end);

    struct hdr_cursor nh = {.pos = data};
    int res, tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct mp_capable *mp_cap;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res <= 20) {
        return action;
    }
    
    //not (syn & ack)
    if (!(tcph->syn && tcph->ack)) {
        return action;
    }

    //get mp capable option
    res = check_mptcp_opt(&nh, data_end, tcphl - 20, 0);
    if (res < 0) {
        //without mp_capable
        return action;
    }
    mp_cap = (struct mp_capable*)(nh.pos);
    CHECK_BOUND_BY_SIZE(mp_cap, data_end, offsetof(struct mp_capable, receiver_key));

    struct mp_capable_event_t event;
    __builtin_memset(&event, 0, sizeof(event));

    event.connect.saddr = iph->saddr;
    event.connect.daddr = iph->daddr;
    event.connect.source = tcph->source;
    event.connect.dest = tcph->dest;
    event.sender_key = mp_cap->sender_key;

    res = bpf_perf_event_output(skb, &mp_capable_perf_output, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return action;

out_of_bound:
    return action;
}

char _license[] SEC("license") = "GPL";
