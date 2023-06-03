#ifndef EMPTCP_UTILS_H
#define EMPTCP_UTILS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "common.h"
#include "error.h"
#include "events_def.h"


#define SWAP(type, lhp, rhp){\
    type tmp = (*((type*)(lhp))) ^ (*((type*)(rhp)));\
    (*((type*)(lhp))) = tmp ^ (*((type*)(lhp)));\
    (*((type*)(rhp))) = tmp ^ (*((type*)(rhp)));\
}\

#define CHECK_RES(res){                 \
    if ((res) < 0) {                    \
        goto fail;                      \
    }                                   \
}                                       \

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

#define SCAN_TCP_OPT(pos, de, k){\
    struct tcp_option *opt = (pos);\
    CHECK_BOUND(opt, (de));\
    if (opt->kind == k){\
        goto found;\
    }\
    if (opt->kind == 0 || opt->kind == 1) {\
        pos += 1;\
    }\
    else {\
        pos += opt->len;\
    }\
}\


//pos should be type void*, find spefic mptcp opt 
#define SCAN_MPTCP_OPT_SUB(pos, de, sub){\
    struct mptcp_option *opt = (pos);\
    CHECK_BOUND(opt, (de));\
    if (opt->kind == MPTCP_KIND && opt->sub == (sub)){\
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
    if (opt->kind == MPTCP_KIND){\
        goto found;\
    }\
    if (opt->kind == 0 || opt->kind == 1) {\
        pos += 1;\
    }\
    else {\
        pos += opt->len;\
    }\
}

#define CHECK_SELECTOR_NOMATCH(op){     \
   if ((op) == SELECTOR_OR) {           \
        goto next_or;                      \
   } else if((op)== SELECTOR_AND) {    \
        goto not_target;                \
   } else {                             \
        goto fail;                      \
   }                                    \
}                                       

#define CHECK_SELECTOR_MATCH(op){     \
   if ((op) == SELECTOR_OR) {           \
        goto exit;                      \
   } else if((op)== SELECTOR_AND) {    \
        goto next_and;                \
   } else {                             \
        goto fail;                      \
   }                                    \
} 

#define TC_POLICY_PRE_SEC \
    tc_policy_t POLICY; \
    res = tc_get_and_pop_policy(ctx, &POLICY);\
    CHECK_RES(res);\
    __u8 NEXT_IDX = POLICY.chain.next_idx;

#define XDP_POLICY_PRE_SEC \
    xdp_policy_t POLICY; \
    res = xdp_get_and_pop_policy(ctx, &POLICY);\
    CHECK_RES(res);\
    __u8 NEXT_IDX = POLICY.chain.next_idx;

#define TC_SELECTOR_PRE_SEC \
    TC_POLICY_PRE_SEC  \
    tc_selector_t *SELECTOR = (tc_selector_t*)(&POLICY); \
    __u8 SELECTOR_OP = SELECTOR->op;

#define TC_SELECTOR_POST_SEC \
    if (ACTION_CHAIN_ID == NULL) { \
        CHECK_SELECTOR_NOMATCH(SELECTOR_OP); \
    }                                   \
    CHECK_SELECTOR_MATCH(SELECTOR_OP);   \
next_or:\
    if (NEXT_IDX == DEFAULT_POLICY) {   \
        goto not_target;                \
    }                                   \
    goto next_selector;                     \
next_and:                                        \
    if (NEXT_IDX == DEFAULT_POLICY) {            \
        goto exit;                               \
    }                                            \
    goto next_selector;                              \
exit:                                             \
    tc_clear_policy_chain(ctx);                    \
    tc_set_action_chain_id(ctx, ACTION_CHAIN_ID);\
    goto action_entry;   

#define TC_ACTION_POST_SEC \
next:                                   \
    if (NEXT_IDX == DEFAULT_POLICY) {\
        goto exit;                   \
    }                                \
    goto next_action;

#define XDP_SELECTOR_PRE_SEC \
    XDP_POLICY_PRE_SEC  \
    xdp_selector_t *SELECTOR = (xdp_selector_t*)(&POLICY); \
    __u8 SELECTOR_OP = SELECTOR->op;

//res next_idx , fail, not_target

#define XDP_SELECTOR_POST_SEC \
    if (ACTION_CHAIN_ID == NULL) { \
        CHECK_SELECTOR_NOMATCH(SELECTOR_OP); \
    }                                   \
    CHECK_SELECTOR_MATCH(SELECTOR_OP);   \
next_or:\
    if (NEXT_IDX == DEFAULT_POLICY) {   \
        goto not_target;                \
    }                                   \
    goto next_selector;                     \
next_and:                                        \
    if (NEXT_IDX == DEFAULT_POLICY) {            \
        goto exit;                               \
    }                                            \
    goto next_selector;                              \
exit:                                             \
    res = xdp_clear_policy_chain(ctx, NEXT_IDX);  \
    CHECK_RES(res);\
    res = xdp_set_action_chain_id(ctx, ACTION_CHAIN_ID);\
    CHECK_RES(res);\
    goto action_entry;

#define XDP_ACTION_POST_SEC \
next:                                   \
    if (NEXT_IDX == DEFAULT_POLICY) {\
        goto exit;                   \
    }                                \
    goto next_action;

#ifdef NOBCC
static __always_inline __sum16 csum16_add(__sum16 csum, __be16 addend)
{
	__u16 res = (__u16)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}
static __always_inline __sum16 csum16_sub(__sum16 csum, __be16 addend)
{
	return csum16_add(csum, ~addend);
}

/* Implements RFC 1624 (Incremental Internet Checksum)
 * 3. Discussion states :
 *     HC' = ~(~HC + ~m + m')
 *  m : old value of a 16bit field
 *  m' : new value of a 16bit field
 */
static __always_inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new)
{
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}
#endif 

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

static __always_inline int check_tcp_opt(struct hdr_cursor *nh, void *data_end, int tcp_opt_len, int kind) {
/*
 * param: 
 *      nh : cursor 
 *      data_end : packet data_end 
 *      tcp_opt_len : tcp opt length parse from tcp header 
 *      sub : tcp option kind 
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
        if (curr_idx == index) SCAN_TCP_OPT(pos, data_end, kind);
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

static __always_inline int check_mptcp_opts(
        struct hdr_cursor *nh, 
        void *data_end, 
        int tcp_opt_len, 
        __u32 opt_flags) {
/*
 * param: 
 *      nh : cursor 
 *      data_end : packet data_end 
 *      tcp_opt_len : tcp opt length parse from tcp header 
 *      opt_flags: opts to be get, after call flags set to opt flags  found
 *      opts: got mptcp opts
 *      len: Max opts len, after this call set to opts num found
 * return: 
 *      0 : success , nh move to the address opt found 
 *      -1 : fail
 */
    void *pos = nh->pos;
    void *start = pos;
    struct mptcp_option *opt;
    #pragma unroll
    for (int index = 0; index < 40; index++) {
        int curr_idx = pos - start;
        if (curr_idx >= tcp_opt_len) goto finish;
        if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
        continue;
found:
        opt = (struct mptcp_option*)pos;
        CHECK_BOUND(opt, data_end);
        if (opt_flags & (1 << opt->sub)) {
            goto finish;
        }
        pos += opt->len;
    }
//not found mptcp opt 
    return 1;
finish:
    nh->pos = pos;
    return 0;

out_of_bound:
    return -CHECK_MPTCP_OPTS_FAIL;
}

static __always_inline void scan_mptcp_opts(
        const struct hdr_cursor *nh, void *data_end, int tcp_opt_len, __u32 *opt_flags) {

    void *start = nh->pos;
    void *pos = start;
    struct mptcp_option *opt;
    #pragma unroll 40
    for (int index = 0; index < 40; index++) {
        int curr_idx = pos - start;
        if (curr_idx >= tcp_opt_len) return;
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

//return 0 if success
//return negative if failed 
static __always_inline int xdp_get_policy(struct xdp_md *ctx, xdp_policy_t *p) {
    void *data = (void *)(__u64)(ctx->data);
    void *data_meta = (void *)(__u64)(ctx->data_meta);
    
    if(data_meta + sizeof(xdp_policy_t) > data) {
        return -XDP_GET_POLICY_FAIL;
    }
    __builtin_memcpy(p, data_meta, sizeof(xdp_policy_t));
    return 0;
}

//return 0 if success
//negative if fail
static __always_inline int xdp_pop_policy(struct xdp_md *ctx) {
    long res; 
    res = bpf_xdp_adjust_meta(ctx, sizeof(xdp_policy_t));
    if (res < 0) {
        return -XDP_POP_POLICY_FAIL;
    } else {
        return 0;
    }
}

//return 0 if success
static __always_inline int tc_get_and_pop_policy(struct __sk_buff *ctx, tc_policy_t *p) {
    __builtin_memcpy(p, &(ctx->cb[1]), 4);
#pragma unroll 
    for (int i = 1; i < TC_CB_MAX_LEN-1; i++) {
        ctx->cb[i] = ctx->cb[i+1];
    }
    return 0;
}       

//return 0 if success
static __always_inline int xdp_get_and_pop_policy(struct xdp_md *ctx, xdp_policy_t *p) {
    int res;
    res = xdp_get_policy(ctx, p);
    if (res < 0) {
        goto fail;
    }

    //pop action
    res = xdp_pop_policy(ctx);
    if (res < 0) {
        goto fail;
    }
    
    return 0;

fail:
    return res;
}

static __always_inline void tc_get_action_chain_id(struct __sk_buff *ctx, action_chain_id_t *chain) {
    __builtin_memcpy((void*)(chain), &ctx->cb[0], 4);
    __builtin_memcpy((void*)(chain) + 4, &ctx->cb[1], 4);
    ctx->cb[0] = 0;
    ctx->cb[1] = 0;
}

//return 0 if success
//return negative if failed 
static __always_inline int xdp_get_action_chain_id(struct xdp_md *ctx, action_chain_id_t *chain) {
    int res;
    void *data = (void *)(__u64)(ctx->data);
    void *data_meta = (void *)(__u64)(ctx->data_meta);
    
    if(data_meta + sizeof(action_chain_id_t) > data) {
        goto fail;
    }
    __builtin_memcpy(chain, data_meta, sizeof(action_chain_id_t));
    res = bpf_xdp_adjust_meta(ctx, sizeof(action_chain_id_t));
    if (res < 0) {
        goto fail;
    }
    return 0;
fail:
    return -XDP_GET_ACTION_CHAIN_ID_FAIL;
}

static __always_inline void tc_set_action_chain_id(struct __sk_buff *ctx, const action_chain_id_t *chain) {
    // action_chain_id is 64bit 8bytes 
    //low 4 bytes 
    __builtin_memcpy(&(ctx->cb[0]), (void*)chain, 4);
    //high 4 bytes 
    __builtin_memcpy(&(ctx->cb[1]), (void*)chain + 4, 4);
}

static __always_inline int xdp_set_action_chain_id(struct xdp_md *ctx, const action_chain_id_t *chain) {
    int res;
    res = bpf_xdp_adjust_meta(ctx, -(int)sizeof(action_chain_id_t));
    if (res < 0) {
        goto fail;
    }
    void *data = (void *)(__u64)(ctx->data);
    void *data_meta = (void *)(__u64)(ctx->data_meta);
    
    if(data_meta + sizeof(action_chain_id_t) > data) {
        goto fail;
    }
    __builtin_memcpy(data_meta, chain, sizeof(action_chain_id_t));
    return 0;
fail:
    return -XDP_SET_ACTION_CHAIN_ID_FAIL;
}

static __always_inline void get_tcp2tuple_in(const struct iphdr *iph, struct tcp2tuple *tcp2t) {
    tcp2t->local_addr = iph->daddr;
    tcp2t->remote_addr = iph->saddr;
}

static __always_inline void get_tcp2tuple_out(const struct iphdr *iph, struct tcp2tuple *tcp2t) {
    tcp2t->local_addr = iph->saddr;
    tcp2t->remote_addr = iph->daddr;
}

static __always_inline void get_tcp4tuple_in(const struct iphdr *iph,  const struct tcphdr *tcph, struct tcp4tuple *tcp4t) {
    tcp4t->local_addr = iph->daddr;
    tcp4t->remote_addr = iph->saddr;
    tcp4t->local_port = tcph->dest;
    tcp4t->remote_port = tcph->source;
}

static __always_inline void get_tcp4tuple_out(const struct iphdr *iph,  const struct tcphdr *tcph, struct tcp4tuple *tcp4t) {
    tcp4t->local_addr = iph->saddr;
    tcp4t->remote_addr = iph->daddr;
    tcp4t->local_port = tcph->source;
    tcp4t->remote_port = tcph->dest;
}

#define NORMAL_H_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

#define COPY_TCP_OPT_FROM_P(index, tcp_opt_len, dst, pkt_src, de){              \
    if ((index) >= (tcp_opt_len)) goto out;                                     \
    CHECK_BOUND_BY_SIZE(pkt_src, de, 4);                                        \
    __builtin_memcpy((void*)(dst),(void*)(pkt_src),4);                          \
    (pkt_src) = (void*)(pkt_src) + 4;                                           \
    (dst) = (void*)(dst) + 4;                                                   \
}\

#define COPY_TCP_OPT_TO_P(index, tcp_opt_len, pkt_dst, src, de){                \
    if ((index) >= (tcp_opt_len)) goto out;                                     \
    CHECK_BOUND_BY_SIZE(pkt_dst, de, 4);                                        \
    __builtin_memcpy((void*)(pkt_dst),(void*)(src),4);                          \
    (src) = (void*)(src) + 4;                                                   \
    (pkt_dst) = (void*)(pkt_dst) + 4;                                                   \
}\

struct pkt_header_buf_t {
    char normal_header[NORMAL_H_LEN];
    char tcp_opts[40];
};


//return 0 success 
//return negative if fail
static __always_inline int store_header(struct pkt_header_buf_t *temp, struct hdr_cursor *nh, void *data_end, __u16 tcp_opt_len) {
    void *pkt_src = nh->pos;

    CHECK_BOUND_BY_SIZE(pkt_src, data_end, NORMAL_H_LEN)
    __builtin_memcpy(&temp->normal_header, pkt_src, NORMAL_H_LEN);
    pkt_src += NORMAL_H_LEN;

    void *dst = (void*)(&temp->tcp_opts);
    __u16 tl4 = tcp_opt_len >> 2;  
    COPY_TCP_OPT_FROM_P(0, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(1, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(2, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(3, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(4, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(5, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(6, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(7, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(8, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(9, tl4, dst, pkt_src, data_end);

out_of_bound: 
    return -1;

out: 
    nh->pos = (void*)pkt_src;
    return 0;
}

//if success return 0
//else return -1
static __always_inline int recover_header(const struct pkt_header_buf_t *temp, struct hdr_cursor *nh, void *data_end, __u16 tcp_opt_len) {
    void *pkt_dst = nh->pos;
    CHECK_BOUND_BY_SIZE(pkt_dst, data_end, NORMAL_H_LEN);
    __builtin_memcpy(pkt_dst, &temp->normal_header, NORMAL_H_LEN);
    pkt_dst += NORMAL_H_LEN;

    __u16 tl4 = tcp_opt_len >> 2;  

    void *src = (void*)(&temp->tcp_opts);

    COPY_TCP_OPT_TO_P(0, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(1, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(2, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(3, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(4, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(5, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(6, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(7, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(8, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(9, tl4, pkt_dst, src, data_end);

out_of_bound:
    return -1;
out:
    nh->pos = pkt_dst;
    return 0;
}

static __always_inline void update_tcphlen_csum(
    struct iphdr *iph,
    struct tcphdr *tcph,    
    int adjust
)
{
    int tot_len, tcp_totlen;
    tot_len = bpf_ntohs(iph->tot_len);
    tcp_totlen = tot_len - 20;

    //update ip header and checksum (tot_len)
    iph->tot_len = bpf_htons(tot_len + adjust);
    csum_replace2(&iph->check, bpf_htons(tot_len), iph->tot_len);  //update checksum

    //update tcp checksum
    //update presudo header
    csum_replace2(&tcph->check, bpf_htons(tcp_totlen), bpf_htons(tcp_totlen + adjust));

    //update tcp header len
    struct tcp_flags *tfp;
    __be16 old_tfp;

    size_t off = offsetof(struct tcphdr, ack_seq) + sizeof(__be32);
    tfp = (void*)tcph + off;

    __builtin_memcpy((void*)&old_tfp, (void*)tfp, 2);
    tfp->doff += (adjust >> 2);
    csum_replace2(&tcph->check, old_tfp, *((__be16*)tfp));
}

//对于数据包来说，无法直接使用 xdp_adjust_tail helper 
//supposed that we don't contains IP opts 
//return 0 if success
//return negative if fail
static __always_inline int xdp_grow_tcp_header(struct xdp_md *ctx, struct hdr_cursor *nh,  __u16 tcp_opt_len, int bytes, int *modified) {
    if (bytes <= 0 || bytes > 40 - tcp_opt_len) {
        *modified = 0;
        goto fail;
    }
    void * data = (void *)(long)ctx->data;
    void * data_end =  (void *)(long)ctx->data_end; 
    nh->pos = data;

    int res;
    struct pkt_header_buf_t buf;

    //1. store header to buf
    res = store_header(&buf, nh, data_end, tcp_opt_len);
    if (res < 0) {
        *modified = 0;
        goto fail;
    }

    //2. grow header
    res = bpf_xdp_adjust_head(ctx, -bytes);
    if (res < 0) {
        *modified = 1;
        goto fail;
    }

    //3 reset data and data_end
    data =  (void *)(long)ctx->data; 
    data_end =  (void *)(long)ctx->data_end; 

    //4. recover header 
    nh->pos = data;
    res = recover_header(&buf, nh, data_end, tcp_opt_len);
    if (res < 0) {
        *modified = 1;
        goto fail;
    }
    return 0;

fail:
    return -1;
}

//#define TC_HEADER_NORMAL_LEN sizeof(struct iphdr) + sizeof(struct tcphdr) 
#define TC_HEADER_NORMAL_LEN 20

struct tc_pkt_header_buf_t {
    char normal_header[TC_HEADER_NORMAL_LEN];
    char tcp_opts[40];
};


static __always_inline int tc_store_header(struct tc_pkt_header_buf_t *temp, struct hdr_cursor *nh, void *data_end, __u16 tcp_opt_len) {
    void *pkt_src = nh->pos;

    CHECK_BOUND_BY_SIZE(pkt_src, data_end, TC_HEADER_NORMAL_LEN)
    __builtin_memcpy(&temp->normal_header, pkt_src, TC_HEADER_NORMAL_LEN);
    pkt_src += TC_HEADER_NORMAL_LEN;

    void *dst = (void*)(&temp->tcp_opts);
    __u16 tl4 = tcp_opt_len >> 2;  
    COPY_TCP_OPT_FROM_P(0, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(1, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(2, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(3, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(4, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(5, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(6, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(7, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(8, tl4, dst, pkt_src, data_end);
    COPY_TCP_OPT_FROM_P(9, tl4, dst, pkt_src, data_end);

out_of_bound: 
    return -1;

out: 
    nh->pos = (void*)pkt_src;
    return 0;
}

static __always_inline int tc_recover_header(const struct tc_pkt_header_buf_t *temp, struct hdr_cursor *nh, void *data_end, __u16 tcp_opt_len) {
    void *pkt_dst = nh->pos;
    CHECK_BOUND_BY_SIZE(pkt_dst, data_end, TC_HEADER_NORMAL_LEN);
    __builtin_memcpy(pkt_dst, &temp->normal_header, TC_HEADER_NORMAL_LEN);
    pkt_dst += TC_HEADER_NORMAL_LEN;

    __u16 tl4 = tcp_opt_len >> 2;  

    void *src = (void*)(&temp->tcp_opts);

    COPY_TCP_OPT_TO_P(0, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(1, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(2, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(3, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(4, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(5, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(6, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(7, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(8, tl4, pkt_dst, src, data_end);
    COPY_TCP_OPT_TO_P(9, tl4, pkt_dst, src, data_end);

out_of_bound:
    return -1;
out:
    nh->pos = pkt_dst;
    return 0;
}

static __always_inline int tc_grow_tcp_header(struct __sk_buff *ctx, struct hdr_cursor *nh,  __u16 tcp_opt_len, int bytes, int *modified) {
    if (bytes <= 0 || bytes >= 40 - tcp_opt_len) {
        *modified = 0;
        goto fail;
    }
    int res; 
    void * data = (void *)(long)ctx->data;

    void * data_end =  (void *)(long)ctx->data_end; 
    nh->pos = data + NORMAL_H_LEN - TC_HEADER_NORMAL_LEN;

    struct tc_pkt_header_buf_t buf;
    __builtin_memset(&buf, 0, sizeof(struct tc_pkt_header_buf_t));

    //1. store header to buf
    res = tc_store_header(&buf, nh, data_end, tcp_opt_len);
    if (res < 0) {
        *modified = 0;
        goto fail;
    }

    //2. grow header
    res = bpf_skb_adjust_room(ctx, bytes, BPF_ADJ_ROOM_NET, 0);
    if (res < 0) {
        *modified = 1;
        goto fail;
    }

    //3 reset data and data_end
    data =  (void *)(long)ctx->data; 
    data_end =  (void *)(long)ctx->data_end; 

    //4. recover header 
    nh->pos = data + NORMAL_H_LEN - TC_HEADER_NORMAL_LEN;
    res = tc_recover_header(&buf, nh, data_end, tcp_opt_len);
    if (res < 0) {
        *modified = 1;
        goto fail;
    }
    return 0;

fail: 
    return -1;
}

static __always_inline void add_tcpopt_csum(__sum16 *csum, const void *src, __u16 size) {
    __u16 s2 = size >> 1;
    __sum16 check = ~(*csum);
    const __be16 *begin = src;
#pragma unroll 20 
    for (int i = 0; i < 20; i++) {
        if (i >= s2) break;
        check = csum16_add(check, *begin++);
    }
    *csum = ~check;
}

//this function must be called after  xdp_grow_tcp_header (to  ensure csum is right)
//return 0 if success 
//return negative if fail
static __always_inline int add_tcp_opts(struct hdr_cursor *nh, void *data_end, const void *opts, __u16 size) {
    if (opts == NULL) goto fail;
    if ((size & 0x3) != 0) {
        //size % 4 != 0
        goto fail;
    }

    void *pkt_dst = nh->pos;
    const void *src = opts;
    __u16 s4 = size >> 2;  

#pragma unroll 10
    for (int i = 0; i < 10; i++) {
        COPY_TCP_OPT_TO_P(i, s4, pkt_dst, src, data_end);
    out:
        break;
    }

    nh->pos = pkt_dst;
    return 0;

out_of_bound:
fail:
    return -1;
}

static __always_inline void set_tcp_nop(__u8 *dst) {
    *dst = 0x01;
}

static __always_inline void set_tcp_nop2(__u16 *dst) {
    *dst = 0x0101;
}

static __always_inline int rm_tcp_header(struct hdr_cursor *nh, void *data_end, struct tcphdr *tcph, __u16 size, int *modified) {
    //set option to nop and update checksum 
    if ((size & 0x1) != 0) {
        //size % 2 != 0
        *modified = 0;
        goto fail;
    }

    __u16 *pkt = nh->pos;
    __u16 s2 = size >> 1;  

    *modified = 1;
#pragma unroll 20
    for (int i = 0; i < 20; i++) {
        if (i >= s2) break;
        CHECK_BOUND(pkt, data_end);
        __u16 old = *pkt;
        //set nop
        set_tcp_nop2(pkt);
        csum_replace2(&tcph->check, old, 0x0101);
        pkt++;
    }

    nh->pos = pkt;
    return 0;

out_of_bound:
fail:
    return -1;  
}

static __always_inline void tc_set_policy_chain(struct __sk_buff *ctx, tc_policy_t policies[MAX_POLICY_LEN], __u8 *first_policy) {     
    *first_policy = policies[0].chain.idx;
    __u8 policy_num = 0;
    #pragma unroll
    for (int i = 0;  i < MAX_POLICY_LEN - 1; i++) {
        int policy = policies[i].chain.idx;
        if (policy == DEFAULT_POLICY) {
            goto set;
        }
        policies[i].chain.next_idx = policies[i+1].chain.idx;
        __builtin_memcpy(&ctx->cb[i+1], &(policies[i]), sizeof(tc_policy_t));
        policy_num++;    
    }
    int last_policy = policies[MAX_POLICY_LEN - 1].chain.idx;
    if (last_policy != DEFAULT_POLICY) {
        policies[MAX_POLICY_LEN - 1].chain.next_idx = DEFAULT_POLICY;
        __builtin_memcpy(&ctx->cb[MAX_POLICY_LEN], &(policies[MAX_POLICY_LEN - 1]), sizeof(tc_policy_t));
        policy_num++; 
    }

set:
    if (policy_num == 0) {
        return;
    }

    tc_chain_meta_t meta;
    __builtin_memset(&meta, 0, sizeof(tc_chain_meta_t));
    meta.idx = 1;    //ctx->cb[1]
    meta.len = policy_num;
    __builtin_memcpy(&ctx->cb[0], &meta, sizeof(tc_chain_meta_t));
    return;
}

// return 0 if success else return -1 
static __always_inline int xdp_set_policy_chain(struct xdp_md *ctx, xdp_policy_t policies[MAX_POLICY_LEN], __u8 *first_policy) {
    //遍历几个字节的事情，我觉得开销应该不会特别大
    int res;
    __u8 policy_num = 0;

    #pragma unroll
    for (int i = 0; i < MAX_POLICY_LEN; i++) {
        int policy = policies[i].chain.idx;
        if (policy == DEFAULT_POLICY) break;
        policy_num++;    
    }
    if (policy_num == 0) {
        *first_policy = DEFAULT_POLICY;
        return 0;
    }
       
    *first_policy = policies[0].chain.idx;

    #pragma unroll 
    for (int i = 0; i < MAX_POLICY_LEN - 1; i++) {
        policies[i].chain.next_idx = policies[i+1].chain.idx;
    }
    policies[MAX_POLICY_LEN - 1].chain.next_idx = DEFAULT_POLICY;
    
    //adjust xdp_meta and set action chain to xdp_meta 
    res = bpf_xdp_adjust_meta(ctx, -(policy_num * sizeof(xdp_policy_t)));
    if (res < 0) {
        return -XDP_ADJUST_META_FAIL;
    }
    
    void *data = (void *)(__u64)(ctx->data);
    void *pos = (void *)(__u64)(ctx->data_meta);
    void *policy = policies;

    #pragma unroll MAX_POLICY_LEN
    for (int i = 0; i < MAX_POLICY_LEN; i++) {
        if (i >= policy_num) break;
        if (pos + sizeof(xdp_policy_t) > data) {
            return -XDP_ADJUST_META_FAIL;
        }
        __builtin_memcpy(pos, policy, sizeof(xdp_policy_t));
        pos += sizeof(xdp_policy_t);
        policy += sizeof(xdp_policy_t);
    }
    return 0;
}

static __always_inline void tc_clear_policy_chain(struct __sk_buff *ctx) {
    __builtin_memset(ctx->cb, 0 , 4 * TC_CB_MAX_LEN);
    //ctx->cb[0] = 0;
    //ctx->cb[1] = 0;
    //ctx->cb[2] = 0;
    //ctx->cb[3] = 0;
    //ctx->cb[4] = 0;
}

//return 0 success
//return -1 failed
static __always_inline int xdp_clear_policy_chain(struct xdp_md *ctx, __u8 next_idx) {
    if (next_idx == DEFAULT_POLICY) return 0;
     
    int res;
    __u8 count = 0;

    void *data = (void *)(__u64)(ctx->data);
    xdp_policy_t *p = (void *)(__u64)(ctx->data_meta);
    
    #pragma unroll 
    for (int i = 0; i < MAX_POLICY_LEN; i++) {
        if ((void*)(p + 1) > data) {
            goto fail;
        }
        next_idx = p->chain.next_idx;
        if (next_idx == DEFAULT_POLICY) {
            break;
        }
        count++;
        p+=1;
    }
    res = bpf_xdp_adjust_meta(ctx, count * sizeof(xdp_policy_t));
    if (res < 0) goto fail;
    return 0;
fail:
    return -XDP_CLEAR_SELECTOR_CHAIN_FAIL;
}

static __always_inline void pre_copy_tcp_pkt(void *data_end, const struct ethhdr *eth, const struct iphdr *iph, const struct tcphdr *tcph, mptcp_copy_pkt_event *e) {
    e->header.time_ns = bpf_ktime_get_ns();
    e->header.len = sizeof(e);
    
    get_tcp4tuple_in(iph, tcph, &e->flow);
    __builtin_memcpy(&e->eth, eth, sizeof(struct ethhdr));
    e->window = tcph->window;
    e->seq = tcph->seq;
    e->ack_seq = tcph->ack_seq; 
}

static __always_inline int pre_copy_mptcp_pkt(void *data_end, const struct ethhdr *eth, const struct iphdr *iph, const struct tcphdr *tcph, const struct mp_dss *dss, mptcp_copy_pkt_event *e) {

    pre_copy_tcp_pkt(data_end, eth, iph, tcph, e);
    __builtin_memcpy(&e->dss_opt, dss, sizeof(struct mp_dss));
    void *dss_ack = (void*)(dss + 1);
    if (dss->a) {
        //8bytes 
        CHECK_BOUND_BY_SIZE(dss_ack, data_end, 8);
        __builtin_memcpy(&e->dss_ack, dss_ack, 8);
    } else {
        //4 bytes
        CHECK_BOUND_BY_SIZE(dss_ack, data_end, 4);
        __builtin_memcpy(&e->dss_ack, dss_ack, 4);
    }
    return 0;

out_of_bound:
    return -1; //should not happen 
}

static __always_inline void record_pkt(__u32 *pkt) {
    *pkt += 1;
}

static __always_inline void record_flow_size(__u64 *flow_size, const struct iphdr *iph, const struct tcphdr *tcph) {
    __u64 data_len = (__u64)(iph->tot_len - (iph->ihl << 2) - (tcph->doff << 2));
}

static __always_inline void record_rtt(__u32* rtt_array, __u32* producer,  const struct tcp_timestamp_opt *opt) {
    *(rtt_array + (((*producer)++) & TCP_METRIC_MAX_RTT_MASK)) = (__u32)bpf_ktime_get_ns() - opt->ts_echo;
}

typedef unsigned long long u64;

#ifdef DEBUG

#define DEBUG_DATA_DEF_SEC \
struct {                        \
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
    __type(key, int);                           \
    __type(value, int);                          \
    __uint(max_entries, MAX_DEBUG_EVENTS_SIZE);   \
} debug_events SEC(".maps");          

#define INIT_DEBUG_EVENT(e) \
    struct debug_time_event_t debug_time_event; \
    __builtin_memset(&debug_time_event, 0, sizeof(struct debug_time_event_t));  \
    debug_time_event.event = e;

#define RECORD_DEBUG_EVENTS(stage) { \
    debug_time_event.stage = bpf_ktime_get_ns();                             \
}\

#define SEND_DEBUG_EVENTS       \
    bpf_perf_event_output(ctx, &debug_events, BPF_F_CURRENT_CPU, &debug_time_event, sizeof(struct debug_time_event_t)); \

#endif 
#endif
