#ifndef _MPTCP_META_CTX_MAP_H
#define _MPTCP_META_CTX_MAP_H

#include "vmlinux_v0.h"
#include "mptcp_meta_ctx.h"
#include <bpf/bpf_helpers.h>

#define MAX_MPTCP_TCP_CONN_NUM 10000

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct tcp4tuple);
	__type(value, u64);
	__uint(max_entries, MAX_MPTCP_TCP_CONN_NUM);
	__uint(pinning, 1);
} mptcp_subflow_key_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MAX_MPTCP_TCP_CONN_NUM);
	__uint(pinning, 1);
}  mptcp_token_key_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct emptcp_ctx);
	__uint(max_entries,1);
	__uint(pinning, 1);
} emptcp_ctx_map SEC(".maps"); 

#endif 