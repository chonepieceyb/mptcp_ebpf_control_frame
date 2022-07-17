#include "common.h"
#include "utils.h"
#include "error.h"
// #include  "/usr/include/bcc/compat/linux/bpf.h"

#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];

	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	__be32 tmp = iphdr->saddr;

	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

static __always_inline void recompute_tcph_csum(struct tcphdr *tcph, struct iphdr *iph, __u16 new_tcphl) {
    //set checksum to zero 
    tcph->check = 0;
    __sum16 check = 0;
    
    __be16 *begin;  // every 2 bytes 

    //compute predo header 
    begin = (__be16*)(&iph->saddr);
    
    //ip saddr and daddr   4W
    #pragma unroll 4
    for (int i = 0; i < 4; i++) {
        check = csum16_add(check, *begin);
        begin++;
    }
    
    //add Protocol and TCP length (in our case equals tcphl)
    check = csum16_add(check, 0x0600);
    check = csum16_add(check, bpf_htons(new_tcphl));

    //add checksum for tcp header 40bytes 20W
    begin = (__be16*)tcph;

    #pragma unroll 20
    for (int i = 0; i < 20; i++) {
        check = csum16_add(check, *begin);
        begin++;
    }
    tcph->check = ~check;
}

#ifdef NOBCC
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_TC_EGRESS_ACTION_NUM);
} tc_egress_actions SEC(".maps");

#else

BPF_TABLE_PINNED("prog", int, int, tc_egress_actions, MAX_TC_EGRESS_ACTION_NUM, TC_EGRESS_ACTIONS_PATH);

#endif

#ifdef NOBCC
SEC("tc")
#endif 
int buffer_echo(struct __sk_buff *ctx) {
    int res;

    //TC_POLICY_PRE_SEC

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

    // no tcp option
    if (tcphl <= 20) {
        return TC_ACT_OK;
    }

    if (tcph->syn) {
        return TC_ACT_OK; 
    }

    char *payload = data + sizeof(*eth) + sizeof(*iph) + tcphl;
    CHECK_BOUND(payload, data_end);
    // if((void*)(payload+1) > data_end){
    //     goto out_of_bound;
    // }

    swap_src_dst_mac(eth);
    swap_src_dst_ipv4(iph);

    // int shrink_delta = (int)tcphl - 20;

    //change tot_len and update checksum
    __be16 new_tlen = bpf_htons(60);
    csum_replace2(&iph->check, iph->tot_len, new_tlen);  //update checksum 
    iph->tot_len = new_tlen;

    //no need to update checksum 
    SWAP(__be16, &tcph->source, &tcph->dest);

    //ack + 1428
    __be32 new_seq;
    __be32 new_acks;
    new_seq = tcph->ack_seq;
    new_acks = bpf_htonl(bpf_ntohl(tcph->seq) + 1428);

    //update doff and flags 
    // struct tcp_flags *tfp;

    // size_t off = offsetof(struct tcphdr, ack_seq) + sizeof(__be32);
    
    // tfp = (void*)tcph + off; 

    //update doff and flags 
    // tfp->doff = 40 >> 2; 
    // tfp->psh = 0;

    tcph->seq = new_seq;
    tcph->ack_seq = new_acks;

    tcph->doff = 40 >> 2;
    tcph->psh = 0;

    res = check_mptcp_opt(&nh, data_end, tcphl-20, MPTCP_SUB_DSS);

    if(res < 0){
        goto fail;
    }

    struct mp_dss *dss = nh.pos;
    CHECK_BOUND(dss, data_end);

    __be32 *data_ack = (void*)(dss+1);
    CHECK_BOUND(data_ack, data_end);

    __be32 *dss_num =(void*)(dss+2);
    CHECK_BOUND(dss_num, data_end);

    __be32 dss_num_v = *dss_num;
    __be32 new_data_ack = bpf_htonl(bpf_ntohl(dss_num_v) + 1428);

    *data_ack = new_data_ack;
    dss->len = 8;
    dss->M = 0;

    __be32 *option = data + sizeof(*eth) + sizeof(*iph) + 20;
    if((void*)(option+5)>data_end){
        goto fail;
    }

    recompute_tcph_csum(tcph, iph, 40);

    //shrink packet first
    res = bpf_skb_change_tail(ctx, 74, 0);

    if (res) {
        // adjust packet space
       return TC_ACT_SHOT;
    }

    return bpf_redirect(2,BPF_F_INGRESS);
    // return bpf_redirect(2, 0);

out_of_bound:
fail: 
    return TC_ACT_UNSPEC;

exit:
    //bpf_trace_printk("finish!");
    return TC_ACT_UNSPEC;
}
#ifdef NOBCC
char _license[] SEC("license") = "GPL";
#endif 
