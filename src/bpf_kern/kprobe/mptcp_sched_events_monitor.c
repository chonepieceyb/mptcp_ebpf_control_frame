#include "mptcp_sched.h"
#include "mptcp_sched_map_def.h"
#include "vmlinux.h"
#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "error.h"

char _license[] SEC("license") = "GPL";

#define  KPROBE_READ(src)								\
({											\
	typeof((src)) __res;								\
	bpf_probe_read_kernel((void*)&__res, sizeof(__res), (void*)&(src));		\
	__res;										\
})

static __always_inline void copy_subflow_4_tuple(struct tcp4tuple *dst, const struct sock *sk)
{
	dst->remote_port = KPROBE_READ(sk->__sk_common.skc_dport);
	dst->local_port = bpf_htons(KPROBE_READ(sk->__sk_common.skc_num));  /*host to network*/
	dst->remote_addr = KPROBE_READ(sk->__sk_common.skc_daddr);
	dst->local_addr = KPROBE_READ(sk->__sk_common.skc_rcv_saddr);
}

static __always_inline int event_established_handler(const struct mptcp_sock *msk, const struct sock *ssk)
{
	int res;
	mptcp_key_type key = KPROBE_READ(msk->local_key);
	struct mptcp_conn_meta conn_meta; 
	__builtin_memset(&conn_meta, 0, sizeof(conn_meta));
	copy_subflow_4_tuple(&conn_meta.connlist[0], ssk);
	conn_meta.socklist[0] = (void*)ssk;
	conn_meta.num = 1;
	
	/* TODO: more reduant*/
	return bpf_map_update_elem(&mptcp_key_mapping, &conn_meta.connlist[0], &key, BPF_NOEXIST)
		|| bpf_map_update_elem(&mptcp_conns, &key, &conn_meta, BPF_NOEXIST);
	return 0;
}

static __always_inline int event_close_handler(const struct mptcp_sock *msk, const struct sock *ssk)
{
	mptcp_key_type key = KPROBE_READ(msk->local_key);
	struct mptcp_conn_meta *old_conn_meta;
	old_conn_meta = bpf_map_lookup_elem(&mptcp_conns, &key);
	if (old_conn_meta == NULL) {
		bpf_printk("bug: key not found in close handler\n");
		return -1;
	}
	/*TDOD maintain the subflows as well*/
	bpf_map_delete_elem(&mptcp_key_mapping, &old_conn_meta->connlist[0]);
	bpf_map_delete_elem(&mptcp_conns, &key);
	return 0;
}

static __always_inline int event_sub_established_handler(const struct mptcp_sock *msk, const struct sock *ssk)
{
	int next;
	mptcp_key_type key = KPROBE_READ(msk->local_key);
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

	return bpf_map_update_elem(&mptcp_key_mapping, &new_conn_meta.connlist[next], &key, BPF_NOEXIST) ||
		bpf_map_update_elem(&mptcp_conns, &key, &new_conn_meta, BPF_EXIST);
}

static  __always_inline int event_sub_close_handler(const struct mptcp_sock *msk, const struct sock *ssk)
{
	int i, num;
	int found = -1;
	mptcp_key_type key = KPROBE_READ(msk->local_key);
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
			found = i;
			break;
		}
	}
	if (found == -1) {
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
	bpf_map_delete_elem(&mptcp_key_mapping, &old_conn_meta->connlist[found]);
	return bpf_map_update_elem(&mptcp_conns, &key, &new_conn_meta, BPF_EXIST);
}

SEC("kprobe/mptcp_event")
int BPF_KPROBE(mptcp_event_monitor, enum mptcp_event_type type, const struct mptcp_sock *msk, const struct sock *ssk, gfp_t gfp)
{	
	int res; 
	bpf_printk("debug: mptcp event type %d\n", type);
	if (msk == NULL) {
		bpf_printk("bug msk is null\n");
		return -1;
	}
	
	if (KPROBE_READ(msk->sk.icsk_inet.sk.__sk_common.skc_family) == AF_INET6) {
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
		bpf_printk("handler mptcp event error: err%d, event %d\n", res, type);
	}
	//write the fd of open syscall to BPF ARRAY
	return 0;
}