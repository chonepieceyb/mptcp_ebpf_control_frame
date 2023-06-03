#include "mptcp_sched.h"
#include "mptcp_sched_map_def.h"
#include "vmlinux.h"
#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "error.h"

char _license[] SEC("license") = "GPL";

static __always_inline void copy_subflow_4_tuple(struct tcp4tuple *dst, const struct sock *sk)
{
	dst->remote_port = sk->__sk_common.skc_dport;
	dst->local_port = bpf_htons(sk->__sk_common.skc_num);  /*host to network*/
	dst->remote_addr = sk->__sk_common.skc_daddr;
	dst->local_addr = sk->__sk_common.skc_rcv_saddr;
}

static __always_inline int event_established_handler(const struct mptcp_sock *msk, const struct sock *ssk)
{
	mptcp_key_type key = msk->local_key;
	struct mptcp_conn_meta conn_meta; 
	__builtin_memset(&conn_meta, 0, sizeof(conn_meta));
	copy_subflow_4_tuple(&conn_meta.connlist[0], ssk);
	conn_meta.socklist[0] = (void*)ssk;
	conn_meta.num = 1;
	return bpf_map_update_elem(&mptcp_conns, &key, &conn_meta, BPF_NOEXIST);
}

static __always_inline int event_close_handler(const struct mptcp_sock *msk, const struct sock *ssk)
{
	mptcp_key_type key = msk->local_key;
	return bpf_map_delete_elem(&mptcp_conns, &key);
}

static __always_inline int event_sub_established_handler(const struct mptcp_sock *msk, const struct sock *ssk)
{
	int next;
	mptcp_key_type key = msk->local_key;
	struct mptcp_conn_meta *old_conn_meta;
	struct mptcp_conn_meta new_conn_meta;
	old_conn_meta = bpf_map_lookup_elem(&mptcp_conns, &key);
	if (old_conn_meta == NULL) {
		bpf_printk("bug: MPTCP_MONITOR_NOEXIST\n");
		return -1;
	}
		
	next = (old_conn_meta->num) & (MPTCP_SUBFLOW_MAX - 1);
	if (next <= 0) {
		bpf_printk("bug: MPTCP_MONITOR_FULL\n");
		return -1;
	}
	__builtin_memcpy(&new_conn_meta, old_conn_meta, sizeof(new_conn_meta));
	/* add to the tail*/
	copy_subflow_4_tuple(&new_conn_meta.connlist[next], ssk);
	new_conn_meta.socklist[next] = (void*)ssk;
	new_conn_meta.num = next + 1;
	return bpf_map_update_elem(&mptcp_conns, &key, &new_conn_meta, BPF_EXIST);
}

static  __always_inline int event_sub_close_handler(const struct mptcp_sock *msk, const struct sock *ssk)
{
	int i, num;
	bool found = false;
	mptcp_key_type key = msk->local_key;
	struct mptcp_conn_meta *old_conn_meta;
	struct mptcp_conn_meta new_conn_meta;
	__builtin_memset(&new_conn_meta, 0, sizeof(new_conn_meta));
	old_conn_meta = bpf_map_lookup_elem(&mptcp_conns, &key);
	if (old_conn_meta == NULL) {
		bpf_printk("bug: MPTCP_MONITOR_NOEXIST\n");
		return -1;
	}
	num =  old_conn_meta->num;
	for (i = 0; i < MPTCP_SUBFLOW_MAX && i < num; i++) {
		if (old_conn_meta->socklist[i] != (void*)ssk) {
			/*not the deleted one*/
			__builtin_memcpy(&new_conn_meta.connlist[i], &old_conn_meta->connlist[i], sizeof(struct tcp4tuple));
			new_conn_meta.socklist[i] = old_conn_meta->socklist[i];
		} else {
			found = true;
			break;
		}
	}
	if (!found) {
		bpf_printk("bug: delete subflow not found");
		return -1;
	}
	i += 1;
	/*copy the left ones*/
	for (; i < MPTCP_SUBFLOW_MAX && i < num; i++) {
		__builtin_memcpy(&new_conn_meta.connlist[i-1], &old_conn_meta->connlist[i], sizeof(struct tcp4tuple));
		new_conn_meta.socklist[i-1] = old_conn_meta->socklist[i];
	}
	new_conn_meta.num = num - 1;
	return bpf_map_update_elem(&mptcp_conns, &key, &new_conn_meta, BPF_EXIST);
}

SEC("kprobe/__sys_connect")
int BPF_KPROBE(mptcp_event, 
	       enum mptcp_event_type type, 
	       const struct mptcp_sock *msk,
	       const struct sock *ssk, 
	       gfp_t gfp)
{	
	int res; 
	if (msk->sk.icsk_inet.sk.__sk_common.skc_family == AF_INET6) {
		return 0;
	}
	
	switch(type) {
	case MPTCP_EVENT_ESTABLISHED:
		res = event_established_handler(msk, ssk);
		break;
	case MPTCP_EVENT_SUB_ESTABLISHED:
		res = event_sub_established_handler(msk, ssk);
		break;
	case MPTCP_EVENT_CLOSED:
		res = event_close_handler(msk, ssk);
		break;
	case MPTCP_EVENT_SUB_CLOSED:
		res = event_sub_close_handler(msk, ssk);
		break;
	default:
		res = 0;
	}

	if (res < 0) {
		bpf_printk("handler mptcp event error: err\n", res);
	}
	//write the fd of open syscall to BPF ARRAY
	return 0;
}