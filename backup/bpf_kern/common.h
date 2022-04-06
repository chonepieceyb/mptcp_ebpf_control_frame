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

#endif 
