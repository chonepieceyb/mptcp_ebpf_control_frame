
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define MPTCP_SUBFLOWS_MAX 8

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;
extern void mptcp_sched_data_set_contexts(const struct mptcp_sock *msk,
					  struct mptcp_sched_data *data) __ksym;

extern bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;

extern long mptcp_timeout_from_subflow(const struct mptcp_subflow_context *subflow) __ksym;

extern void mptcp_set_timeout(struct sock *sk) __ksym;

extern bool mptcp_subflow_stream_memory_free(const struct mptcp_subflow_context *subflow) __ksym;

SEC("struct_ops/mptcp_sched_minrtt_init")
void BPF_PROG(mptcp_sched_minrtt_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_minrtt_release")
void BPF_PROG(mptcp_sched_minrtt_release, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/bpf_minrtt_data_init")
void BPF_PROG(bpf_minrtt_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
        mptcp_sched_data_set_contexts(msk, data);
}

SEC("struct_ops/bpf_minrtt_get_subflowmm")
int BPF_PROG(bpf_minrtt_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	//bpf_printk("bpf_debug: minrtt begin");
	
       	u32 min_srtt = ~(u32)0;
       	int nr = 0;
       	struct tcp_sock *tcp_sk;
       	for (int i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
		if (data->contexts[i] == NULL) {
			break;
		}
		tcp_sk = bpf_skc_to_tcp_sock(data->contexts[i]->tcp_sock);
		if (tcp_sk == NULL) {
			bpf_printk("bug: skc to tcp sock failed i %d\n", i);
			break;
		}
		if (tcp_sk->srtt_us < min_srtt) {
			min_srtt = tcp_sk->srtt_us;
			nr = i;
		}
        } 
	mptcp_subflow_set_scheduled(data->contexts[nr], 1);
	mptcp_set_timeout((struct sock*)msk);
	//bpf_printk("bpf_debug: minrtt nr %d, min_rtt %lu \n", nr, min_srtt);
	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops minrtt = {
	.init		= (void *)mptcp_sched_minrtt_init,
	.release	= (void *)mptcp_sched_minrtt_release,
	.data_init	= (void *)bpf_minrtt_data_init,
	.get_subflow	= (void *)bpf_minrtt_get_subflow,
	.name		= "bpf_minrtt",
};