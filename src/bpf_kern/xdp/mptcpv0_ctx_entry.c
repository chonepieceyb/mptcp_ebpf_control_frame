#include "common_new.h"
#include "mptcp_meta_ctx_maps.h"
#include "error.h"
#include "utils_new.h"

#define TC_ACT_UNSPEC -1
#define NEXT_IDX 0

SEC("xdp")
int xdp_ctx_entry(struct xdp_md *ctx) {
    int res;

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
        goto exit;
    }

    /*get and parse emptcp ctx*/
    struct emptcp_ctx *__ctx_emptcp;
    int key = 0;
    __ctx_emptcp = bpf_map_lookup_elem(&emptcp_ctx_map, &key);
    if (__ctx_emptcp == NULL) {
        log_error("failed to get ctx_mptcp");
        goto fail; 
    }
    get_tcp4tuple_in(iph, tcph, &__ctx_emptcp->tcp4);
    struct mptcp_subflow_est_info *est_info = bpf_map_lookup_elem(&mptcp_subflow_key_map, &__ctx_emptcp->tcp4);
    if (est_info == NULL) {
        goto exit;
    }

    __ctx_emptcp->mptcp_loc_key = est_info->mptcp_loc_key;
    __ctx_emptcp->is_meta = est_info->is_meta;

    /*jump to the next idx 0*/
    bpf_tail_call(ctx, &xdp_actions_new, NEXT_IDX);

out_of_bound:
fail: 
    return XDP_PASS;

exit:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";