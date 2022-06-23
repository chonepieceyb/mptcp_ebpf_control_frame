#ifndef MPTCP_EBPF_CONTROL_FRAME_H
#define MPTCP_EBPF_CONTROL_FRAME_H

#include <linux/stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "common.h"

#ifdef NOBCC

#include <linux/bpf.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#endif

#define SWAP(type, lhp, rhp){\
    type tmp = (*((type*)(lhp))) ^ (*((type*)(rhp)));\
    (*((type*)(lhp))) = tmp ^ (*((type*)(lhp)));\
    (*((type*)(rhp))) = tmp ^ (*((type*)(rhp)));\
}\

#define CHECK_BOUND(p,data_end){\
    if ((void*)((p) + 1) > (data_end)) {\
        goto out_of_bound;\
    }\
}\

#define CHECK_BOUND_BY_SIZE(p,data_end,size){\
    if (((void*)(p) + size) > (data_end)) {\
        goto out_of_bound;\
    }\
}\

//pos should be type void*, find spefic mptcp opt 
#define SCAN_MPTCP_OPT_SUB(pos, de, sub){\
    struct mptcp_option *opt = (pos);\
    CHECK_BOUND(opt, (de));\
    if (opt->kind == 30 && opt->sub == (sub)){\
        goto found;\
    }\
    if (opt->kind == 0 || opt->kind == 1) {\
        pos += 1;\
    }\
    else {\
        pos += opt->len;\
    }\
}\

#define SCAN_MPTCP_OPT(pos, de){\
    struct mptcp_option *opt = (pos);\
    CHECK_BOUND(opt, (de));\
    if (opt->kind == 30){\
        goto found;\
    }\
    if (opt->kind == 0 || opt->kind == 1) {\
        pos += 1;\
    }\
    else {\
        pos += opt->len;\
    }\
}\

static __always_inline void move_cursor(struct hdr_cursor *nh, int bytes) {
    nh->pos += bytes;
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;

    CHECK_BOUND(eth, data_end);
    move_cursor(nh, sizeof(struct ethhdr));

    *ethhdr = eth;
    return eth->h_proto; /* network-byte-order */

out_of_bound:
    //out of bound 
    return -1;
}

//需要考虑ip options
static __always_inline int parse_ipv4hdr(struct hdr_cursor *nh,
        void *data_end,
        struct iphdr **iphdr) 
{
    //nh pos move to he next header(skip header options)
    struct iphdr *iph = nh->pos;
     
    CHECK_BOUND(iph, data_end);

    int hl = iph->ihl << 2;  
    
    //we supposed we don't have ip options
    //can be optimized
    if (hl != 20) {
        return -1;
    }

    move_cursor(nh, sizeof(struct iphdr));

    *iphdr = iph;
    //after parse pos move to the begin of next protocol 
    //return iphdr->protocol
    return iph->protocol;

out_of_bound:
    return -1;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *nh, 
        void *data_end,
        struct tcphdr **tcphdr) {
    //after parse pos point to the begin of tcp options
    //return tcp header length(>=20) to check weather carray a tcp option
    struct tcphdr *tcph = nh->pos;

    CHECK_BOUND(tcph, data_end);
    move_cursor(nh, sizeof(struct tcphdr));

    *tcphdr = tcph;
    int hlen = tcph->doff;
    return hlen << 2;  //不知道直接获取对不对，先这样

out_of_bound:
    return -1;
}

//if contains tcp packet return tcp header length(>=20)  
//, else return -1
static __always_inline int is_tcp_packet(struct hdr_cursor *nh, void *data_end, struct ethhdr **eth, struct iphdr **iph, struct tcphdr **tcph) {
    int res;
    res  = parse_ethhdr(nh, data_end, eth); 
    if (res != bpf_htons(ETH_P_IP)) {
        return -1;
    }

    // parse ipv4 header
    res = parse_ipv4hdr(nh, data_end, iph);
    if (res != IPPROTO_TCP) {
        return -1;
    }
    
    // parse tcp header 
    return parse_tcphdr(nh, data_end, tcph); //返回tcp头部的长度
}


static __always_inline int check_mptcp_opt(struct hdr_cursor *nh, void *data_end, int tcp_opt_len, int sub) {

/*
 * param: 
 *      nh : cursor 
 *      data_end : packet data_end 
 *      tcp_opt_len : tcp opt length parse from tcp header 
 *      sub : mptcp sub 
 *      mp_opt : if mptcp options exists, mp_opt is set 
 * return: 
 *      0 : success , nh move to the address opt found 
 *      -1 : bpf bound check failed, nh keep no change
 *      -2 : mptcp options not exists, nh keep no change 
 */
    void *start = nh->pos;
    void *pos = start;
    #pragma unroll 40
    for (int index = 0; index < 40; index++) {
        int curr_idx = pos - start;
        if (curr_idx >= tcp_opt_len) goto not_exists;
        if (curr_idx == index) SCAN_MPTCP_OPT_SUB(pos, data_end, sub);
    }
found:
    //found mptcp option
    nh->pos = pos;
    return 0;

out_of_bound:

    return -1;

not_exists:

    return -2; 
}

static __always_inline void check_mptcp_opts(
        const struct hdr_cursor *nh, void *data_end, int tcp_opt_len, __u32 *opt_flags) {

    void *start = nh->pos;
    void *pos = start;
    struct mptcp_option *opt;
    #pragma unroll 40
    for (int index = 0; index < 40; index++) {
        int curr_idx = pos - start;
        if (curr_idx >= tcp_opt_len) return;
/*
        if (curr_idx == index) {
            opt = (pos);
            CHECK_BOUND(opt, data_end);
            if (opt->kind == 30){
                *opt_flags |= (1 << opt->sub);
                pos += opt->len;

            }
            if (opt->kind == 0 || opt->kind == 1) {
                pos += 1;
            }
            else {
                pos += opt->len;
            }
        }
*/
        if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
        continue;
found:
        opt = (struct mptcp_option*)pos;
        CHECK_BOUND(opt, data_end);
        *opt_flags |= (1 << opt->sub);
        pos += opt->len;

    }
out_of_bound:

    return;
}

static __always_inline int cal_segment_len(const struct iphdr *iph, const struct tcphdr *tcph) {
    //previous check ensure that iphl = 20, if condition changed, changed here too 
    int tot_len= bpf_htons(iph->tot_len);
    return tot_len - 20 - ((tcph->doff) << 2);
}

#endif 

