#include "common_new.h"
#include "mptcp_meta_ctx_maps.h"
#include "error.h"
#include "utils_new.h"

#define MPTCP_SUB_TS 10

struct mp_timestamp {
	__u8	kind;
	__u8	len;
    __u8	b:1,
            rsv:3,
            sub:4;
    __be32   timestamp_us;
} __attribute__((__packed__));

SEC("xdp")
int parse_mptcp_ts(struct xdp_md *ctx) {
    int res;
    int modified = 0;
    
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
        goto exit;
    }
    
    //only work on tcp ack 
    if (!(tcph->ack && !tcph->syn)) {
        goto exit;
    }
    
    //get addr option
    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_TS);
    if (res < 0) {
        bpf_printk("not find timestamp option\n");
        goto exit;
    }

    bpf_printk("find timestamp option\n");

    struct mptcp_option *mptcp_opt = nh.pos;
    CHECK_BOUND(mptcp_opt, data_end);

    if (mptcp_opt->len != sizeof(struct mp_timestamp)) {
        goto fail;
    }
    
    struct mp_timestamp *mp_ts_p = nh.pos;
    CHECK_BOUND(mp_ts_p, data_end);
    
    bpf_printk("timestamp is :%u", mp_ts_p->timestamp_us);

    /*remove mptcp_ts*/
    res = rm_tcp_header(&nh, data_end, tcph, mptcp_opt->len, &modified);

    //bpfprintk("rm add addr end res: %d\n", res);
    if (res < 0) {
        goto fail;
    }

    /*TODO: write timestamp to emptcp_ctx*/

out_of_bound:
fail:
    if (modified) {
        return XDP_DROP;
    } else {
        return XDP_PASS;
    }
exit:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";