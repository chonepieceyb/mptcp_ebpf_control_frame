#include "common_new.h"
#include "mptcp_meta_ctx_maps.h"
#define __TARGET_ARCH_x86
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "error.h"


char _license[] SEC("license") = "GPL";

#define KPROBE_READ(src)								\
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

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

static inline bool mptcp(const struct tcp_sock *tp)
{
	u32 mpc_flags = 0; 
	bpf_probe_read_kernel(&mpc_flags, sizeof(mpc_flags), (void*)tp + offsetof(struct tcp_sock, meta_sk) + sizeof(void*));
	return mpc_flags & 0x1;
}

static inline bool is_slave_sk(const struct tcp_sock *tp) 
{
	struct mptcp_tcp_sock *mptcp; 
	mptcp = KPROBE_READ(tp->mptcp);
	if (mptcp == NULL)
		return false;
	u16 slave_flags = 0;
	bpf_probe_read_kernel(&slave_flags, sizeof(slave_flags), (void*)mptcp + offsetof(struct mptcp_tcp_sock, map_data_len) + sizeof(u16));
	return slave_flags & 0x1;
}	

static inline struct tcp_sock *mptcp_meta_tp(const struct tcp_sock *tp)
{
	return (struct tcp_sock *)(KPROBE_READ(tp->meta_sk));
}

static inline int is_meta_tp(const struct tcp_sock *tp)
{
	return KPROBE_READ(tp->mpcb) && mptcp_meta_tp(tp) == tp;
}


static inline int is_master_tp(const struct tcp_sock *tp)
{

	return mptcp(tp) || (!is_slave_sk(tp) && !is_meta_tp(tp));
}

SEC("kprobe/full_mesh_new_session")
int BPF_KPROBE(full_mesh_new_session_handler, struct sock *meta_sk)
{	
	/*a new mptcp connection is created*/
	struct mptcp_cb *mpcb = KPROBE_READ(tcp_sk(meta_sk)->mpcb);
	struct tcp4tuple flow_key;
	struct mptcp_subflow_est_info est_info; 
	__builtin_memset(&flow_key, 0, sizeof(flow_key));
	__builtin_memset(&est_info, 0, sizeof(est_info));
	copy_subflow_4_tuple(&flow_key, meta_sk);
	est_info.mptcp_loc_key = KPROBE_READ(mpcb->mptcp_loc_key);
	est_info.is_meta = 1;
	u32 mptcp_rem_token =  KPROBE_READ(mpcb->mptcp_rem_token);
	bpf_printk("mptcp rem token %u\n", mptcp_rem_token);
	bpf_map_update_elem(&mptcp_token_key_map, &mptcp_rem_token, &est_info.mptcp_loc_key , 1);
	bpf_map_update_elem(&mptcp_subflow_key_map, &flow_key, &est_info, 1);  //BPF_NOEXIST
	return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state_handler, struct sock *sk, int state)
{	
	if (state != TCP_CLOSE)
		return 0;
	struct tcp4tuple flow_key;
	__builtin_memset(&flow_key, 0, sizeof(flow_key));
	copy_subflow_4_tuple(&flow_key, sk);
	bpf_map_delete_elem(&mptcp_subflow_key_map, &flow_key);
	if (is_meta_tp(tcp_sk(sk))) {
		struct sock *meta_sk = KPROBE_READ(((struct tcp_sock*)sk)->meta_sk);
		struct mptcp_cb *mptcp = KPROBE_READ(((struct tcp_sock*)meta_sk)->mpcb);
		u32 remote_token = KPROBE_READ(mptcp->mptcp_rem_token);
		bpf_printk("delete key token entry\n");
		bpf_map_delete_elem(&mptcp_token_key_map, &remote_token);
	}
  	return 0;
}