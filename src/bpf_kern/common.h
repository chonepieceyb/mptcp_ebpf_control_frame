#ifndef EMPTCP_COMMON_H
#define EMPTCP_COMMON_H

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/in6.h>

#ifndef BCC_SEC

#define NOBCC

#endif 


#ifdef NOBCC

#include <stddef.h>
#include <linux/bpf.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

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

struct tcp_option {
    __u8 kind;
    __u8 len;
};

struct tcp_timestamp_opt {
    __u8 kind;
    __u8 len;
    __be32 ts;
    __be32 ts_echo;
} __attribute__((__packed__));


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
struct tcp4tuple {
    __be16	local_port;
    __be16	remote_port;
    __be32      local_addr;
    __be32	remote_addr;
};

//for test 
struct tcp2tuple {
    __be32      local_addr;
    __be32      remote_addr;
};

typedef __u64 action_chain_id_t;

/* 
 *bpf data struct define 
 */

/*
#define MAX_XDP_ENTRY_NUM 32
#define XDP_ENTRIES_PATH "/sys/fs/bpf/eMPTCP/xdp_entries"
*/

#define DEFAULT_POLICY 0

//XDP

#define XDP_ACTION_ENTRY DEFAULT_POLICY

#define MAX_XDP_SELECTOR_NUM 32
#define XDP_SELECTORS_PATH "/sys/fs/bpf/eMPTCP/xdp_selectors"

#define XDP_SELECTOR_CHAIN_PATH "/sys/fs/bpf/eMPTCP/xdp_selector_chain"

#define MAX_XDP_ACTION_NUM 32
#define XDP_ACTIONS_PATH "/sys/fs/bpf/eMPTCP/xdp_actions"

#define MAX_XDP_ACTION_CHAIN_NUM 200000
#define XDP_ACTION_CHAINS_PATH "/sys/fs/bpf/eMPTCP/xdp_action_chains"

#define MAX_XDP_EMPTCP_EVENTS_SIZE 128

#define MAX_POLICY_LEN 4

//TC Egress
#define TC_CB_MAX_LEN       5
#define TC_EGRESS_ACTION_ENTRY DEFAULT_POLICY

#define MAX_TC_EGRESS_SELECTOR_NUM 32
#define TC_EGRESS_SELECTORS_PATH "/sys/fs/bpf/eMPTCP/tc_egress_selectors"

#define TC_EGRESS_SELECTOR_CHAIN_PATH "/sys/fs/bpf/eMPTCP/tc_egress_selector_chain"

#define MAX_TC_EGRESS_ACTION_NUM 32
#define TC_EGRESS_ACTIONS_PATH "/sys/fs/bpf/eMPTCP/tc_egress_actions"

#define MAX_TC_EGRESS_ACTION_CHAIN_NUM 200000
#define TC_EGRESS_ACTION_CHAINS_PATH "/sys/fs/bpf/eMPTCP/tc_egress_action_chains"

#define MAX_TC_EGRESS_EMPTCP_EVENTS_SIZE 128
#define TC_EGRESS_EMPTCP_EVENTS_PATH "/sys/fs/bpf/eMPTCP/tc_egress_eMPTCP_events"

union chain_t{
    __u8 idx;
    __u8 next_idx;

};

struct policy_t {
    union chain_t chain;
    __u8 rsv1;
    __u8 rsv2;
    __u8 rsv3;
};
typedef struct policy_t xdp_policy_t;
typedef struct policy_t tc_policy_t;

struct chain_meta_t {
    __u8 idx;
    __u8 len;
    __u16 rsv;
};
typedef struct chain_meta_t tc_chain_meta_t;

enum selector_op_type {
    SELECTOR_AND = 0,
    SELECTOR_OR = 1
};

struct selector_t {
    union chain_t chain;
    __u8 op;
    __u16 rsv;
};

typedef struct selector_t xdp_selector_t;
typedef struct selector_t tc_selector_t;

#define SELECTOR_CHAIN_MAX_LEN MAX_POLICY_LEN
struct selector_chain_t {
    struct selector_t selectors[SELECTOR_CHAIN_MAX_LEN];
}n;

typedef struct selector_chain_t xdp_selector_chain_t;
typedef struct selector_chain_t tc_selector_chain_t;

enum param_type {
    IMME = 0,
    MEM = 1,
};

struct action_t {
    union chain_t chain;
    __u8       param_type:2,
               rsv:6;
    union {
        __u16 imme;
        struct {
            __u8 offset;
            __u8 len;
        } mem;
    } param;
};

typedef struct action_t xdp_action_t; 
typedef struct action_t tc_action_t;

#define ACTION_CHAIN_MAX_LEN MAX_POLICY_LEN
struct action_chain_t {
    struct action_t actions[ACTION_CHAIN_MAX_LEN];
    __u32 ref_cnt;
};

typedef struct action_chain_t xdp_action_chain_t;
typedef struct action_chain_t tc_action_chain_t;

struct perf_event_header_t {
    __u64  time_ns;
    __u16  event;
    __u16  len;
};

typedef struct perf_event_header_t eMPTCP_event_header_t;

struct default_action_t {
    action_chain_id_t id;
    int enable;
};

struct mptcp_copy_pkt_event_t {
    eMPTCP_event_header_t header;
    struct tcp4tuple flow;
    struct ethhdr eth;
    __be16 window;
    __be32 seq;
    __be32 ack_seq;
    struct mp_dss dss_opt;
    char dss_ack[8];
};
typedef struct mptcp_copy_pkt_event_t mptcp_copy_pkt_event;

#define TCP_METRIC_MAX_RTT_SHIFT 3
#define TCP_METRIC_MAX_RTT_LEN (1 << TCP_METRIC_MAX_RTT_SHIFT)
#define TCP_METRIC_MAX_RTT_MASK ((TCP_METRIC_MAX_RTT_LEN) - 1)

struct tcp_metrics_t {
    __u32 ingress_pkts;
    __u32 egress_pkts;
    __u64 ingress_flow_size; 
    __u64 egress_flow_size; 
    __u32 rtt_producer;
    __u32 rtts[TCP_METRIC_MAX_RTT_LEN];   
};

typedef struct tcp_metrics_t tcp_metrics;

#ifdef DEBUG

#define MAX_DEBUG_EVENTS_SIZE 128
#define DEBUG_EVENTS_PATH "/sys/fs/bpf/eMPTCP/debug_events"

#define SET_RECV_WIN_EVENT 1
#define SET_FLOW_PRIORITY_EVENT 2
#define RM_ADD_ADDR 3
#define RECOVER_ADD_ADDR 4
#define TCP2SEL 5
#define TCP4SEL 6
#define TCPSEL 7
#define SEL_ENTRY 8 
#define ACTION_ENTRY 9
#define COPY_PKT 10 
#define RECORD 11

struct debug_time_event_t {
    int event;
    __u64 start;
    __u64 end;
};

#endif 

#endif 
