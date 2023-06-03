#ifndef _MPTCP_SCHED_MAP_DEF
#define _MPTCP_SCHED_MAP_DEF

#include "mptcp_sched.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, mptcp_key_type);
	__type(value, struct mptcp_conn_meta);
	__uint(max_entries, MAX_MPTCP_CONN_NUM);
} mptcp_conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, mptcp_key_type);
	__type(value, int);
	__uint(max_entries, MAX_MPTCP_CONN_NUM);
} mptcp_conn_locks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, mptcp_key_type);
	__type(value, int);
	__uint(max_entries, MAX_MPTCP_CONN_NUM);
} mptcp_sched_policies SEC(".maps");

#endif 