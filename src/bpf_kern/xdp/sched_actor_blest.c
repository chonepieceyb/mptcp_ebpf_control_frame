#include "common.h"
#include "utils.h"
#include <linux/ipv6.h>

typedef _Bool bool;
typedef u64 mptcp_key_type;
#define MPTCP_SUBFLOW_MAX_SHIFT 3
#define MPTCP_SUBFLOWS_MAX (1 << MPTCP_SUBFLOW_MAX_SHIFT)
#define MAX_MPTCP_CONN_NUM 20000

struct mptcp_conn_meta {
	int num;
	struct tcp4tuple connlist[MPTCP_SUBFLOWS_MAX];
	void*			 socklist[MPTCP_SUBFLOWS_MAX];                                                                                                                                                                                                                                                                                                                                                                                                          
};

struct emptcp_sched_data {
	void *sk;
	bool scheduled;
};

struct emptcp_sched_policy {
    struct emptcp_sched_data subflows[MPTCP_SUBFLOWS_MAX];
    int snd_burst;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, mptcp_key_type);
	__type(value, struct mptcp_conn_meta);
	__uint(max_entries, MAX_MPTCP_CONN_NUM);
	__uint(pinning, 1);
} mptcp_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tcp4tuple);
	__type(value, mptcp_key_type);
	__uint(max_entries, MAX_MPTCP_CONN_NUM);
	__uint(pinning, 1);
} mptcp_key_mapping SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, mptcp_key_type);
	__type(value, struct emptcp_sched_policy);
	__uint(max_entries, MAX_MPTCP_CONN_NUM);
	__uint(pinning, 1);
} mptcp_sched_policies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, mptcp_key_type);
	__type(value, int);
	__uint(max_entries, MAX_MPTCP_CONN_NUM);
	__uint(pinning, 1);
} mptcp_sched_flags SEC(".maps");

struct subflow_metric_data {
        unsigned long sk_pacing_rate;
        int sk_wmem_queued;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct subflow_metric_data);
	__uint(max_entries, 10000);
        __uint(pinning, 1);
} subflow_metric SEC(".maps");

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y; })

#ifndef __READ_ONCE
#define __READ_ONCE(x)	(*(const volatile typeof(x) *)&(x))
#endif

#define min_t(type, x, y) min((type)(x), (type)(y))

static inline __u64 div_u64_rem(u64 dividend, __u32 divisor, __u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

#ifndef div_u64
static inline __u64 div_u64(u64 dividend, __u32 divisor)
{
	__u32 remainder;
	return div_u64_rem(dividend, divisor, &remainder);
}
#endif


#define LIP_1 3232266968
#define LIP_2 3232266895

#define RIP_1 3232266798
#define RIP_2 3232266822

SEC("xdp")
int sched_actor(struct xdp_md *ctx) {
	int res;
        void *data = (void *)(__u64)(ctx->data);
	void *data_end = (void *)(__u64)(ctx->data_end);
	struct tcp4tuple flow_key;
	u64 *key, *last_snd;
	struct mptcp_conn_meta *conn_meta;
	struct hdr_cursor nh = {.pos = data};
	int tcphl;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph;
    	res = is_tcp_packet(&nh, data_end, &eth, &iph, &tcph);
	if (res < 0) {
		return XDP_PASS;
	}
	get_tcp4tuple_in(iph,  tcph, &flow_key);

	key = bpf_map_lookup_elem(&mptcp_key_mapping, &flow_key);
	if (key == NULL) {
		goto DROP;
	}

	/* try to get flag*/
	res = bpf_map_delete_elem(&mptcp_sched_flags, key);
	if (res < 0) {
		/*not get the flag*/
		return XDP_PASS;
	}
	conn_meta = bpf_map_lookup_elem(&mptcp_conns, key);
	if (conn_meta == NULL) {
		bpf_printk("bug: sched conn_meta not found");
		goto DROP;
	}

	/*scheduler code*/
	struct emptcp_sched_policy policy;
	__builtin_memset(&policy, 0, sizeof(policy));

	/*init scheduler policy*/
	for (int i = 0; i < MPTCP_SUBFLOWS_MAX && i < conn_meta->num; i++) {
		policy.subflows[i].sk = conn_meta->socklist[i];
	}

	/* blest */
	struct mptcp_subflow_context *subflow;
	__u64 min_linger_time = ~(__u64)0;
	__u32 pace, burst, wmem;
	int i, choose_idx = 0;
	struct sock *ssk;
	__u64 linger_time;
	long tout = 0;
	__u32 local_ip, remote_ip;
	struct subflow_metric_data *metric;
	
        for (i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
		/*
		local_ip = bpf_ntohl(conn_meta->connlist[i].local_addr);
		remote_ip = bpf_ntohl(conn_meta->connlist[i].remote_addr);
		if (!((local_ip == LIP_1 && remote_ip == RIP_1) || (local_ip == LIP_2 && remote_ip == RIP_2))) 
			continue;
		*/

		__u64 ssk_key = (__u64)conn_meta->socklist[i];
		metric = bpf_map_lookup_elem(&subflow_metric, &ssk_key);
		if (metric == NULL) 
			continue;
                pace = metric->sk_pacing_rate;
		if (!pace) 
			continue;

		linger_time = div_u64((u64)__READ_ONCE(metric->sk_wmem_queued) << 32, pace);
		if (linger_time < min_linger_time) {
			min_linger_time = linger_time;
			choose_idx = i;
		}	
        }
	
	if (choose_idx >= 0)
		policy.subflows[choose_idx].scheduled = 1;
	bpf_map_update_elem(&mptcp_sched_policies, key, &policy, BPF_ANY);
	bpf_printk("debug: choose_idx : %d, min_linger_time %lu", choose_idx, min_linger_time);
        return XDP_PASS;
DROP:;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";