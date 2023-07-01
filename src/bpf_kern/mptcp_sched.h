#ifndef _MPTCP_SCHED_H
#define _MPTCP_SCHED_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MPTCP_SUBFLOW_MAX_SHIFT 3
#define MPTCP_SUBFLOW_MAX (1 << MPTCP_SUBFLOW_MAX_SHIFT)
#define MAX_MPTCP_CONN_NUM 20000
#define AF_INET6 10

#ifndef TCPTUPLE
#define TCPTUPLE
struct tcp4tuple {
	__be16	local_port;
	__be16	remote_port;
	__be32  local_addr;
	__be32	remote_addr;
};
#endif 

/*the update process of BPF_MAP_TYPE_HASH will hold the bucket lock
* thus we use hashtab to enable locking functionality which means
* for locking calling bpf_map_update_elem with flag BPF_NOEXIST
* if return 0, lock succesfully, otherwise meanning that another BPF program holds the lock
* for unlocking calling bpf_map_delete_elem to delete the key 
*/
static __always_inline int try_bpfhash_lock(void *map, void *key) {
    	int lock = 1;
    	return bpf_map_update_elem(map, key, &lock, BPF_NOEXIST);
}

static __always_inline int bpfhash_lock(void *map, void *key) {
	return bpf_map_delete_elem(map, key);
}

typedef u64 mptcp_key_type;

/*bpf spin lock not supported for kprobe*/
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
	int snd_burst;
};

#endif 