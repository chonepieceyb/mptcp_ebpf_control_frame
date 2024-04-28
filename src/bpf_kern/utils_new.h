#include "common_new.h"

#define NORMAL_H_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

#define CHECK_BOUND_BY_SIZE(p,data_end,size){\
    if (((void*)(p) + size) > (data_end)) {\
        goto out_of_bound;\
    }\
}\

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

/**
 * parse_pkt_5tuple() - Parse into packet 5-tuple.
 * 
 * @nh: Cursor
 * @data_end: `(void *)(long)ctx->data_end`
 * @pkt: Packet 5-tuple to parse into (source/destination IPs/ports are not
 *       converted to host byte order)
 * 
 * Return: 0 if successful, `-EINVAL` if failed to parse.
 */
static __always_inline int32_t parse_pkt_5tuple(struct hdr_cursor *nh,
						void *data_end,
						struct pkt_5tuple *pkt)
{
	struct ethhdr *eth;
	struct iphdr *ip;
	struct __ports *ports;

	eth = nh->pos;
	CHECK_BOUND(eth, data_end);
	if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP))) {
		log_debug(
			" cannot parse pkt_5tuple: unsupported protocol in Ethernet header: %d (!= %d)",
			eth->h_proto, bpf_htons(ETH_P_IP));
		goto unsupported;
	}
	nh->pos += sizeof(*eth);

	ip = nh->pos;
	CHECK_BOUND(ip, data_end);
	if (unlikely(ip->protocol != IPPROTO_TCP &&
		     ip->protocol != IPPROTO_UDP)) {
		log_debug(
			" cannot parse pkt_5tuple: unsupported protocol in IP header %d (not in %d, %d)",
			ip->protocol, IPPROTO_TCP, IPPROTO_UDP);
		goto unsupported;
	}
	nh->pos += sizeof(*ip);

	ports = nh->pos;
	CHECK_BOUND(ports, data_end);

	pkt->src_ip = ip->saddr;
	pkt->dst_ip = ip->daddr;
	pkt->proto = ip->protocol;
	pkt->src_port = ports->src_port;
	pkt->dst_port = ports->dst_port;

	return 0;

out_of_bound:
unsupported:
	return -EINVAL;
}