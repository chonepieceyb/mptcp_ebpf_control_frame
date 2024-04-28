#include "common_new.h"
#include "mptcp_meta_ctx_maps.h"
#include "error.h"
#include "utils_new.h"

#define TC_ACT_UNSPEC          -1
#define TC_ACT_SHOT		2

#define MPTCP_SUB_TS 10

struct mp_timestamp {
	__u8	kind;
	__u8	len;
    __u8	b:1,
            rsv:3,
            sub:4;
    __be32   timestamp_us;
} __attribute__((__packed__));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tcp4tuple);
	__type(value, int);
	__uint(max_entries, MAX_MPTCP_TCP_CONN_NUM);
} mptcp_ts_mark_map SEC(".maps");

static __always_inline void mark_add_mptcp_ts_opt(struct __sk_buff *ctx, void *data_end, int tcphl, const struct iphdr *iph, const struct tcphdr *tcph, void *old_pos) 
{
    __u32 mp_opt_flags = 0;
    int res;
    mp_opt_flags |= MPTCP_SUB_JOIN_FLAG;
    mp_opt_flags |= MPTCP_SUB_CAPABLE_FLAG;
    struct hdr_cursor nh;
    nh.pos = old_pos;
    res = check_mptcp_opts(&nh, data_end, tcphl - 20, mp_opt_flags);
    if (res != 0) {
        return;
    }
    struct tcp4tuple flow_key;
    __builtin_memset(&flow_key, 0, sizeof(flow_key));
    get_tcp4tuple_out(iph, tcph, &flow_key);
    int val = 1; 
    bpf_map_update_elem(&mptcp_ts_mark_map, &flow_key, &val, 0);
}

SEC("tc")
int add_mptcp_ts_option(struct __sk_buff *ctx) {
    void *data = (void *)(__u64)(ctx->data);
    void *data_end = (void *)(__u64)(ctx->data_end);

    struct hdr_cursor nh = {.pos = data};
    int tcphl;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    int res;

    tcphl = res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
    
    if (res < 0) {
        res = -NOT_TCP;
        goto exit;
    }

    //if we check mptcp syn_ack flags, mark this flow we will add timestamp option
    if (tcph->ack && tcph->syn) {
        mark_add_mptcp_ts_opt(ctx, data_end, tcphl, iph, tcph, nh.pos);
        goto exit;
    }

    //only work for data pkt
    if (!(tcph->ack && !tcph->syn)) {
        goto exit;
    }

    /*check ifwe need to add tsoption*/
    struct tcp4tuple flow_key;
    __builtin_memset(&flow_key, 0, sizeof(flow_key));
    get_tcp4tuple_out(iph, tcph, &flow_key);
    int *val = bpf_map_lookup_elem(&mptcp_ts_mark_map, &flow_key);
    if (val == NULL) {
        goto exit;
    }
    if (*val != 1) {
        goto exit;
    }

    //build mp_prio opt 
    struct mp_timestamp mp_ts;
    __builtin_memset(&mp_ts, 0, sizeof(mp_ts));
    mp_ts.kind = MPTCP_KIND;
    mp_ts.sub = MPTCP_SUB_TS;
    mp_ts.len = sizeof(struct mp_timestamp);
    mp_ts.timestamp_us = bpf_htonl(22223);
    int modified; 
    __u16 tcp_opt_len = tcphl - 20;
    res = tc_grow_tcp_header(ctx, &nh, tcp_opt_len, sizeof(mp_ts), &modified);  //nh.pos set to the end 
    if (res < 0) {
        res = -TC_GROW_TCP_HEADER_FAIL;
        goto fail;
    }
    
    data = (void *)(__u64)(ctx->data);
    data_end = (void *)(__u64)(ctx->data_end);

    //get iphdr and tcphdr 
    struct hdr_cursor new_nh;
    new_nh.pos = data;
    res = is_tcp_packet(&new_nh, data_end, &eth, &iph, &tcph);
    if (res < 0) {
        res = -INTERNAL_IMPOSSIBLE;
        goto fail;
    }
    
    //add tcp opts 
    res = add_tcp_opts(&nh, data_end, &mp_ts, sizeof(mp_ts));
    modified = 1;
    if (res < 0) {
        res = -XDP_ADD_TCP_OPT_FAIL;
        goto fail;
    }

    //recompute_csum about packet len 
    update_tcphlen_csum(iph, tcph, sizeof(mp_ts));
    
    //recompute checksum , mp_prio 4 bytes
    add_tcpopt_csum(&tcph->check, &mp_ts, sizeof(mp_ts));

out_of_bound:
fail: 
    log_error("fail, res %d", res);
    if (modified) {
        return TC_ACT_SHOT;
    } else {
        return TC_ACT_UNSPEC;
    }
exit:
    //bpf_trace_printk("finish!");
    return TC_ACT_UNSPEC;
}

#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 