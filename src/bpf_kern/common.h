#ifndef MPTCP_EBPF_CONTROL_FRAME_COMMON_H
#define MPTCP_EBPF_CONTROL_FRAME_COMMON_H

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>

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

#define bpfprintk(fmt, ...)                    \
({                                              \
    char ____fmt[] = fmt;                       \
    bpf_trace_printk(____fmt, sizeof(____fmt),  \
             ##__VA_ARGS__);                    \
})

#ifndef lock_xadd
#define lock_xadd(ptr, val)   __sync_fetch_and_add(ptr, val)
#endif 

#else

#endif

#define MPTCP_KIND                              30

#define MPTCP_SUB_CAPABLE			0
#define MPTCP_SUB_JOIN			        1
#define MPTCP_SUB_DSS		                2

#define MPTCP_SUB_PRIO		                5
#define MPTCP_SUB_LEN_PRIO	                3
#define MPTCP_SUB_LEN_PRIO_ADDR	                4

#define MPTCP_SUB_CAPABLE_FLAG			(1 << 0)
#define MPTCP_SUB_JOIN_FLAG			(1 << 1)
#define MPTCP_SUB_DSS_FLAG		        (1 << 2)

#define MPTCP_SUB_ADD_ADDR		        3

struct tcp_flags {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
};

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
	__u8    len;
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



#define MAIN_FLOW_ID -1

enum direction {
    CLIENT = 0,
    SERVER = 1,
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
    void *pos;
};

#define MAX_SUBFLOW_NUM 200000
/*tcp 4 tuple key 96bytes, network byte order*/
struct tcp_4_tuple {
    __be32      local_addr;
    __be32	peer_addr;
    __be16	local_port;
    __be16	peer_port;
};

//for test 
struct tcp_ip_tuple {
    __be32      local_addr;
    __be32      peer_addr;
};

//typedef struct tcp_4_tuple flow_key_t; 
typedef struct tcp_ip_tuple flow_key_t; 

struct subflow_meta {
    __u8 window_shift;
};

#define MAX_XDP_ACTION_NUM 32
#define XDP_ACTIONS_PATH "/sys/fs/bpf/mptcp_ebpf_control_frame/xdp_actions"
#define SUBFLOW_MAX_ACTION_NUM 4
#define SUBFLOW_PARAM_BYTES 20
#define SUBFLOW_ACTION_INGRESS_PATH "/sys/fs/bpf/mptcp_ebpf_control_frame/subflow_action_ingress"
#define XDP_ACTIONS_FLAG_SIZE 20000
#define XDP_ACTIONS_FLAG_PATH  "/sys/fs/bpf/mptcp_ebpf_control_frame/xdp_actions_flag"


enum param_type {
    IMME = 0,
    MEM = 1,
};

/*
struct action {
    __u8 param_type;
    union {
        __u8 action;
        __u8 next_action;
    } u1;
    union {
        __u16 imme;
        struct {
            __u8 offset;
            __u8 version;  //可以用来判断是否失效
        } mem;
    } u2;
};
*/

struct action_t {
    __u8        param_type:2,
                index:2,
                version:4;
    union {
        __u8 action;
        __u8 next_action;
    } u1;
    union {
        __u16 imme;
        struct {
            __u8 offset;
            __u8 rsv;
        } mem;
    } u2;

};

typedef struct action_t xdp_action_t; 

struct action_flag_key_t {
    flow_key_t flow;
    struct action_t action;
};
typedef struct action_flag_key_t xdp_action_flag_key_t;

typedef __u8 xdp_action_flag_t;

struct subflow_xdp_actions_t {
    xdp_action_t actions[SUBFLOW_MAX_ACTION_NUM];
};

typedef struct subflow_xdp_actions_t xdp_subflow_action_t;

#endif 
