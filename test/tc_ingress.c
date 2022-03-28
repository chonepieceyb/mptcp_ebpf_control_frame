#include "common.h"

struct mp_capable_event_t {
    struct tcp_4_tuple connect; 
    __u64 sender_key;
};

int tc_ingress_main(struct xdp_md *ctx) 
{
    bpf_trace_printk("xdp ingress begin\n");
    int action = 0;

    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int res, tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct mp_capable *mp_cap;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
        bpf_trace_printk("xdp ingress begin2\n");

    if (res <= 20) {
        bpf_trace_printk("not tcp packet: %d\n", res);
        return action;
    }
            bpf_trace_printk("xdp ingress begin3\n");

    //not (syn & ack)
    if (!(tcph->syn && tcph->ack)) {
        bpf_trace_printk("not syn and ack! res: %d\n", res);
        return action;
    }
        bpf_trace_printk("xdp ingress begin4\n");

    //get mp capable option
    res = check_mptcp_opt(&nh, data_end, tcphl - 20, 0);
            bpf_trace_printk("xdp ingress begin5\n");

    if (res < 0) {
        //without mp_capable
        bpf_trace_printk("xdp without mptcp capable event! res: %d tcp opt len %d\n", res, tcphl - 20);
        return action;
    }
    bpf_trace_printk("xdp ingress begin6\n");

    bpf_trace_printk("pos: %d\n", data_end - nh.pos);

    mp_cap = (struct mp_capable*)(nh.pos);
    //CHECK_BOUND(mp_cap, data_end);


    struct mp_capable_event_t event;
    __builtin_memset(&event, 0, sizeof(event));

    event.connect.saddr = iph->saddr;
    event.connect.daddr = iph->daddr;
    event.connect.source = tcph->source;
    event.connect.dest = tcph->dest;
    event.sender_key = mp_cap->sender_key;
    
    bpf_trace_printk("tcp opt len %d", tcphl - 20);
    bpf_trace_printk("send mptcp capable event! res: %d\n", res);
    return 1;

out_of_bound:
    return action;
}

