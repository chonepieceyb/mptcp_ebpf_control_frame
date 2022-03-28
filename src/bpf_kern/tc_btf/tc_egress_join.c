#include "common.h"
#include "error.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct mptcp_connect);
    __uint(max_entries, 100000);
} mptcp_connects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp_4_tuple);
    __type(value, struct subflow);
    __uint(max_entries, 200000);
} subflows SEC(".maps");

/*
struct bpf_map_def SEC("maps") mptcp_connects = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct mptcp_connect),
    .max_entries = 100000,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") subflows = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct tcp_4_tuple),
    .value_size = sizeof(struct subflow),
    .max_entries = 200000,
    .map_flags = BPF_F_NO_PREALLOC,
};
*/

static __always_inline int create_subflow(const struct iphdr *iph, const struct tcphdr *tcph, const struct mp_join *mpj) {
    struct mptcp_connect *mp_connect;
    __u32 flow_index;
    __u32 token = mpj->u.syn.token;  //为了效率直接按照网络字节序存储
    mp_connect = bpf_map_lookup_elem(&mptcp_connects, &token);
    
    if (mp_connect == NULL) return -CREATE_SUB_WITHOUT_TOKEN;
    
    //flow_index = __sync_fetch_and_add(&mp_connect->flow_nums, 1);
    
    //do these in user space
    flow_index = mp_connect->flow_nums;
    bpfprintk("flow_index: %d\n",flow_index);
    mp_connect->flow_nums += 1;

    if (flow_index >= MAX_SUBFLOWS) return -CREATE_SUB_FLOW_MAX;

    struct subflow sub;
    struct tcp_4_tuple flow_key;
    __builtin_memset(&flow_key, 0, sizeof(struct tcp_4_tuple));
    __builtin_memset(&sub, 0, sizeof(struct subflow));
    sub.address_id = mpj->addr_id;
    sub.direction = CLIENT;  //local as client 
    sub.action = -1; 
    sub.token = token; 
    
    flow_key.local_addr = iph->saddr;
    flow_key.peer_addr = iph->daddr;
    flow_key.local_port = tcph->source;
    flow_key.peer_port = tcph->dest;

    //update mptcp_connect
    (mp_connect->subflows)[flow_index] = flow_key;

    //如果出错，可能无法保证subflows 和 mptcp_connects的一致性,但是感觉没有太好的解决方案
    int res;
    res = bpf_map_update_elem(&subflows, &flow_key, &sub, BPF_NOEXIST);
    if (!res) {
        return 0;
    } else {
        return -CREATE_SUB_FLOW_EXISTS;
    }
}

SEC("tc")
int tc_egress_join(struct __sk_buff *skb) {
    int action = -1;

    void *data = (void *)(__u64)(skb->data);
    void *data_end = (void *)(__u64)(skb->data_end);

    struct hdr_cursor nh = {.pos = data};
    int res, tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct mp_join *mpj;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res <= 20) {
        res = -INTERNEL_IMPOSSIBLE;
        goto fail;
    }

    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_JOIN);
    if (res != 0) {
        res = -INTERNEL_IMPOSSIBLE;
        goto fail;
    }
    mpj = (struct mp_join*)nh.pos;
    CHECK_BOUND_BY_SIZE(mpj, data_end, offsetof(struct mp_join, u.syn.nonce));

    res = create_subflow(iph, tcph, mpj);
        
    if (res != 0) {
        goto fail;
    }

success:
    //record time spent in the future 
    bpfprintk("join success! \n");
    return action;

fail:
    //record debug log in the future 
    bpfprintk("join failed! res: %d\n", res);
    return action;

out_of_bound:
    //record debug log in the future 
    bpfprintk("join out of bound! res: %d\n", res);
    return action;
}

char _license[] SEC("license") = "GPL";
