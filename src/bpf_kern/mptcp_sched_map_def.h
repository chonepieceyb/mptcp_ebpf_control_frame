#ifndef _MPTCP_SCHED_MAP_DEF
#define _MPTCP_SCHED_MAP_DEF

#include "mptcp_sched.h"

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

#endif 