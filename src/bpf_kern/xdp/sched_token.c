#include "common.h"
#include "utils.h"

typedef _Bool bool;
typedef u64 mptcp_key_type;
#define MPTCP_SUBFLOW_MAX_SHIFT 3
#define MPTCP_SUBFLOW_MAX (1 << MPTCP_SUBFLOW_MAX_SHIFT)
#define MAX_MPTCP_CONN_NUM 20000

struct tcp4tuple TARGET = {
	.local_addr = 3232266968,
	.remote_addr = 3232266798,
	.local_port = 1,
	.remote_port = 1
};

struct mptcp_conn_meta {
	int num;
	struct tcp4tuple connlist[MPTCP_SUBFLOW_MAX];
	void*			 socklist[MPTCP_SUBFLOW_MAX];                                                                                                                                                                                                                                                                                                                                                                                                          
};

struct emptcp_sched_data {
	void *sk;
	bool scheduled;
};

struct emptcp_sched_policy {
    struct emptcp_sched_data subflows[MPTCP_SUBFLOW_MAX];
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, mptcp_key_type);
	__type(value, u64);
	__uint(max_entries, MAX_MPTCP_CONN_NUM);
	__uint(pinning, 1);
} emptcp_sched_rr_ctx SEC(".maps");


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
	for (int i = 0; i < MPTCP_SUBFLOW_MAX && i < conn_meta->num; i++) {
		policy.subflows[i].sk = conn_meta->socklist[i];
	}
	int nr = 0;
	/* round robin*/
	last_snd = bpf_map_lookup_elem(&emptcp_sched_rr_ctx, key);
	if (last_snd != NULL) {
		for (int i = 0; i < MPTCP_SUBFLOW_MAX && i < conn_meta->num; i++) {
			if (conn_meta->socklist[i] == (void*)(*last_snd)) {
				if (i + 1 == MPTCP_SUBFLOW_MAX || i + 1 == conn_meta->num)
					break; 
				nr = i  + 1;
				break;
			}
		}
	}
	
	policy.subflows[nr].scheduled = 1;
	bpf_map_update_elem(&mptcp_sched_policies, key, &policy, BPF_ANY);
	if (last_snd == NULL) {
		bpf_map_update_elem(&emptcp_sched_rr_ctx, key, &policy.subflows[0].sk, BPF_ANY);
	} else {
		*last_snd = (u64)policy.subflows[nr].sk;
	}
	//bpf_printk("debug: sched actor nr %d\n", nr);
        return XDP_PASS;
DROP:;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";