#ifndef _MPTCP_META_CTX_H
#define _MPTCP_META_CTX_H

#include "vmlinux_v0.h"
#include "common_new.h"

#define MPTCP_MAX_SUBFLOW 16
#define CTX_SIZE 62
#define POLICY_CHAIN_MAX 31

struct mptcp_subflow_est_info {
	u64 mptcp_loc_key; 
	u16 is_meta;
};

struct emptcp_ctx {
	u64 mptcp_loc_key;
	struct tcp4tuple tcp4;
	__u16	is_meta;
	char data[CTX_SIZE];
};

#endif 