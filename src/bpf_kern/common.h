#ifndef MPTCP_EBPF_CONTROL_FRAME_COMMON_H
#define MPTCP_EBPF_CONTROL_FRAME_COMMON_H

#include <linux/stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#ifdef NOBCC

#include <linux/bpf.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef __section
#define __section(x) __attribute((section(x), used))
#endif

#define PIN_NONE 0
#define PIN_OBJECT_NS 1
#define PIN_GLOBAL_NS 2 

/*ELF map definition*/
struct bpf_elf_map {
     __u32 type;
     __u32 size_key;
     __u32 size_value;
     __u32 max_elem;
     __u32 flags;
     __u32 id;
     __u32 pinning;
     __u32 inner_id;
     __u32 inner_idx;
};

#ifndef bpfprintk
#define bpfprintk(fmt, ...)                    \
({                                              \
    char ____fmt[] = fmt;                       \
    bpf_trace_printk(____fmt, sizeof(____fmt),  \
             ##__VA_ARGS__);                    \
})
#endif

#ifndef lock_xadd
#define lock_xadd(ptr, val)   __sync_fetch_and_add(ptr, val)
#endif 

#endif

#define MPTCP_SUB_CAPABLE			0
#define MPTCP_SUB_JOIN			        1
#define MPTCP_SUB_DSS		                2

#define MPTCP_SUB_CAPABLE_FLAG			(1 << 0)
#define MPTCP_SUB_JOIN_FLAG			(1 << 1)
#define MPTCP_SUB_DSS_FLAG		        (1 << 2)

struct mptcp_option {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ver:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};

struct mp_capable {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ver:4,
		sub:4;
	__u8	h:1,
		rsv:5,
		b:1,
		a:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ver:4;
	__u8	a:1,
		b:1,
		rsv:5,
		h:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u64	sender_key;
	__u64	receiver_key;
} __attribute__((__packed__));

struct mp_join {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	b:1,
		rsv:3,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:3,
		b:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u8	addr_id;
	union {
		struct {
			__u32	token;
			__u32	nonce;
		} syn;
		struct {
			__u64	mac;
			__u32	nonce;
		} synack;
		struct {
			__u8	mac[20];
		} ack;
	} u;
} __attribute__((__packed__));

struct mp_dss {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		A:1,
		a:1,
		M:1,
		m:1,
		F:1,
		rsv2:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:3,
		F:1,
		m:1,
		M:1,
		a:1,
		A:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};

struct mp_add_addr {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ipver:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		ipver:4;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u8	addr_id;
	union {
		struct {
			struct in_addr	addr;
			__be16		port;
			__u8		mac[8];
		} v4;
		struct {
			struct in6_addr	addr;
			__be16		port;
			__u8		mac[8];
		} v6;
	} u;
} __attribute__((__packed__));

struct mp_remove_addr {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	rsv:4,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:4;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
	/* list of addr_id */
	__u8	addrs_id;
};

struct mp_fail {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		rsv2:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:8;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be64	data_seq;
} __attribute__((__packed__));

struct mp_fclose {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	rsv1:4,
		sub:4,
		rsv2:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	sub:4,
		rsv1:4,
		rsv2:8;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u64	key;
} __attribute__((__packed__));

struct mp_prio {
	__u8	kind;
	__u8	len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	b:1,
		rsv:3,
		sub:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	sub:4,
		rsv:3,
		b:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__u8	addr_id;
} __attribute__((__packed__));


#define MAX_CONNECT_SIZE 1E7
#define TCP_OPTION_MAX_BYTES 40

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

#define MAIN_FLOW_ID -1

enum direction {
    CLIENT = 0,
    SERVER = 1,
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
    void *pos;
};

/*tcp 4 tuple key 96bytes, network byte order*/
struct tcp_4_tuple {
    __be32      local_addr;
    __be32	peer_addr;
    __be16	local_port;
    __be16	peer_port;
};

struct mp_capable_event_t {
    struct tcp_4_tuple  connect; 
    __u32       sended_data;
    __u64       peer_key;
};

#define MAX_SUBFLOWS 1 << 4
/*mptcp_connects data struct define*/
struct mptcp_connect {
    __u32       flow_nums;    //__syn_fetch_and_add only support 32bit or 64 bit
    struct tcp_4_tuple subflows[MAX_SUBFLOWS];
};

//暂时不加锁
/*subflows*/
struct subflow {
    __s8        address_id;
    __s8        direction;
    __s16       action;
    __u32       token;
    __u32       sended_pkts;
    __u32       recved_pkts;
    __u64       sended_data;
    __u64       recved_data;
};

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
