#include "common_new.h"
#include "mptcp_meta_ctx_maps.h"
#include "error.h"
#include "utils_new.h"

#define TC_ACT_UNSPEC -1

static __always_inline int handle_mpjoin_event(struct __sk_buff *ctx, const struct iphdr *iph, const struct tcphdr *tcph, const struct mp_join *mpj) {
    int res;
    u32 remote_token = 0;
    struct tcp4tuple flow_key; 
    __builtin_memset(&flow_key, 0, sizeof(flow_key));
    get_tcp4tuple_out(iph, tcph, &flow_key);
    remote_token = mpj->u.syn.token;
    u64 *local_key_p = bpf_map_lookup_elem(&mptcp_token_key_map, &remote_token);
    if (local_key_p == NULL) {
        log_debug("failed to get key from  token");
        return -1;
    }
    struct mptcp_subflow_est_info est_info; 
	__builtin_memset(&est_info, 0, sizeof(est_info));
    est_info.mptcp_loc_key = *local_key_p;
    est_info.is_meta = 0;
    return bpf_map_update_elem(&mptcp_subflow_key_map, &flow_key, &est_info, 1);
}

SEC("tc")
int tc_ctx_entry(struct __sk_buff *ctx) {
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
    
    /*
     * 1. catch 3th MP_CAPABLE hand-shake packet
     * 2. catch 1st MP_JOIN 
     * 3. catch fin signal
     */
    
    if ((!tcph->syn) || tcph->ack) {
         /*not the first syn*/
        goto exit;
    }

    __u32 mp_opt_flags = 0;
    mp_opt_flags |= MPTCP_SUB_JOIN_FLAG;
    res = check_mptcp_opts(&nh, data_end, tcphl - 20, mp_opt_flags);
    if (res < 0) {
        res = -CHECK_MPTCP_OPTS_FAIL;
        goto fail;
    }
    if (res == 1) {
        //not found
        goto exit;
    }
    struct mptcp_option *opt = (struct mptcp_option*)(nh.pos);
    CHECK_BOUND(opt,data_end);
    //len == 1

    if (opt->sub != MPTCP_SUB_JOIN) {
       goto exit;
    }

    struct mp_join *mpj = (struct mp_join*)(opt);
    CHECK_BOUND_BY_SIZE(mpj, data_end, offsetof(struct mp_join, u.syn.nonce));
    res = handle_mpjoin_event(ctx, iph, tcph, mpj);
    if (res == 0) 
        goto exit;

out_of_bound:
fail: 
    return TC_ACT_UNSPEC;

exit:
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";