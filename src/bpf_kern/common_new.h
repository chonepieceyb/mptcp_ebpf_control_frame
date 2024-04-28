#ifndef EMPTCP_COMMON_NEW_H
#define EMPTCP_COMMON_NEW_H

#include "vmlinux_v0.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/errno.h>

#ifndef LOG_LEVEL
#define LOG_LEVEL 2
#endif

#define LOG_LEVEL_DEBUG 3
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_ERROR 0

// #define COLOR_RED "\033[0;31m"
// #define COLOR_GREEN "\033[0;32m"
// #define COLOR_YELLOW "\033[1;33m"
// #define COLOR_ORIGIN "\033[0;33m"
// #define COLOR_OFF "\033[0m"

/*
*DEBUG: LEVEL=4
*INFO: LEVEL=3
*WARN: LEVEL=2
*ERROR: LEVEL=1
*/

#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define log_debug(FMT, ...) ({ bpf_printk("[DEBUG]" FMT, ##__VA_ARGS__); })
#else
#define log_debug(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define log_info(FMT, ...) ({ bpf_printk("[INFO]" FMT, ##__VA_ARGS__); })
#else
#define log_info(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_WARN
#define log_warn(FMT, ...) ({ bpf_printk("[WARN]" FMT, ##__VA_ARGS__); })
#else
#define log_warn(fmt, ...) ({})
#endif

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define log_error(FMT, ...) ({ bpf_printk("[ERROR]" FMT, ##__VA_ARGS__); })
#else
#define log_error(fmt, ...) ({})
#endif

#define ANY_IMPL 0
#define EBPF_IMPL 1
#define EBPF_WITH_HYPERCOM_INTRINSIC_IMPL 2
#define HYPERCOM_IMPL 3

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#ifndef build_bug_on
#define build_bug_on(E) ((void)sizeof(char[1 - 2 * !!(E)]))
#endif

#ifndef lock_xadd
#define lock_xadd(P, V) ((void)__sync_fetch_and_add((P), (V)))
#endif

#define LOG2(x)                       \
	({                            \
		unsigned _x = (x);    \
		unsigned _result = 0; \
		while (_x >>= 1) {    \
			_result++;    \
		}                     \
		_result;              \
	})

#define SHIFT_TO_SIZE(_shift) ((unsigned long)1 << (_shift))

#define BOUND_INDEX(idx, shift)                             \
	({                                                  \
		typeof(idx) __idx;                          \
		__idx = (idx) & (SHIFT_TO_SIZE(shift) - 1); \
	})

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

/* linux __ffs software implementation*/
static __always_inline __u64 __ffs64(__u64 word)
{
	int num = 0;

	if ((word & 0xffffffff) == 0) {
		num += 32;
		word >>= 32;
	}
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static __always_inline __u32 __ffs32(__u32 word)
{
	int num = 0;
	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

#define STR(s) #s
#define XSTR(s) STR(s)

#define asm_bound_check(variable, max_size)                        \
	({                                                         \
		asm volatile("%[tmp] &= " XSTR(max_size - 1) " \n" \
			     : [tmp] "+&r"(variable));             \
	})

#define xdp_assert(expr, name)                                                 \
	({                                                                     \
		if (unlikely(!(expr))) {                                       \
			log_error("[xdp assert failed]: unexpected %s", name); \
			goto xdp_error;                                        \
		};                                                             \
	})

#define xdp_assert_eq(expected, actual, name)                                                         \
	({                                                                                            \
		typeof(actual) ___act = (actual);                                                     \
		typeof(expected) ___exp = (expected);                                                 \
		bool ___ok = ___act == ___exp;                                                        \
		if (unlikely(!___ok)) {                                                               \
			log_error(                                                                    \
				"[xdp assert failed]: unexpected %s: actual %lld != expected %lld\n", \
				name, (long long)___act, (long long)___exp);                          \
			goto xdp_error;                                                               \
		};                                                                                    \
	})

#define xdp_assert_neq(noexpected, actual, name)                                                          \
	({                                                                                                \
		typeof(actual) ___act = (actual);                                                         \
		typeof(noexpected) ___noexp = (noexpected);                                               \
		bool ___ok = ___act != ___noexp;                                                          \
		if (unlikely(!___ok)) {                                                                   \
			log_error(                                                                        \
				"[xdp assert failed]: unexpected %s: actual %lld == non expected %lld\n", \
				name, (long long)___act, (long long)___noexp);                            \
			goto xdp_error;                                                                   \
		};                                                                                        \
	})

#define min(x, y)                              \
	({                                     \
		typeof(x) _min1 = (x);         \
		typeof(y) _min2 = (y);         \
		(void)(&_min1 == &_min2);      \
		_min1 < _min2 ? _min1 : _min2; \
	})
#define xdp_assert_tag(expr, name, tag)   \
({                               \
        if (unlikely(!(expr)))  {                            \
                log_error("[xdp assert failed]: unexpected %s", name);                  \
                goto tag;                                         \
        };                                              \
})  

#define xdp_assert_eq_tag(expected, actual, name, tag)   \
({                               				                                                                                            \
	typeof(actual) ___act = (actual);				                                                                                    \
	typeof(expected) ___exp = (expected);				                                                                                    \
	bool ___ok = ___act == ___exp;					                                                                                    \
        if (unlikely(!___ok))  {                                                                                                                            \
                log_error("[xdp assert failed]: unexpected %s: actual %lld != expected %lld\n", name, (long long)___act, (long long)___exp);                  \
                goto tag;                                                                                                                             \
        };                                                                                                                                                  \
}) 

#define xdp_assert_neq_tag(noexpected, actual, name, tag)   \
({                               				                                                                                            \
	typeof(actual) ___act = (actual);				                                                                                    \
	typeof(noexpected) ___noexp = (noexpected);				                                                                                    \
	bool ___ok = ___act != ___noexp;					                                                                                    \
        if (unlikely(!___ok))  {                                                                                                                            \
                log_error("[xdp assert failed]: unexpected %s: actual %lld == non expected %lld\n", name, (long long)___act, (long long)___noexp);                  \
                goto tag;                                                                                                                             \
        };                                                                                                                                                  \
}) 



#define max(x, y)                              \
	({                                     \
		typeof(x) _max1 = (x);         \
		typeof(y) _max2 = (y);         \
		(void)(&_max1 == &_max2);      \
		_max1 > _max2 ? _max1 : _max2; \
	})

#define typecheck(type, x)                     \
	({                                     \
		type __dummy;                  \
		typeof(x) __dummy2;            \
		(void)(&__dummy == &__dummy2); \
		1;                             \
	})

#define CHECK_BOUND(p, data_end)                      \
	do {                                          \
		if ((void *)((p) + 1) > (data_end)) { \
			goto out_of_bound;            \
		}                                     \
	} while (0)

#define ETH_P_IP 0x0800

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct pkt_5tuple {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	uint8_t proto;
} __attribute__((packed));

struct __ports {
	__be16 src_port;
	__be16 dst_port;
} __attribute__((packed));

struct hdr_cursor {
	void *pos;
};

struct tcp4tuple {
    __be16		local_port;
    __be16		remote_port;
    __be32      local_addr;
    __be32		remote_addr;
};

struct tcp_flags {
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
};
#endif