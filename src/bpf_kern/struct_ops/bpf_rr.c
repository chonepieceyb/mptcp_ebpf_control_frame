
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

SEC("struct_ops/mptcp_sched_rr_init")
void BPF_PROG(mptcp_sched_rr_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_rr_release")
void BPF_PROG(mptcp_sched_rr_release, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/bpf_rr_data_init")
void BPF_PROG(bpf_rr_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
        mptcp_sched_data_set_contexts(msk, data);
}

SEC("struct_ops/bpf_rr_get_subflowmm")
int BPF_PROG(bpf_rr_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	int nr = 0;

	for (int i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
		if (!msk->last_snd || !data->contexts[i])
			break;

		if (data->contexts[i]->tcp_sock == msk->last_snd) {
			if (i + 1 == MPTCP_SUBFLOWS_MAX || !data->contexts[i + 1])
				break;

			nr = i + 1;
			break;
		}
	}
	mptcp_subflow_set_scheduled(data->contexts[nr], true);
	mptcp_set_timeout((struct sock*)msk);
	return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops rr = {
	.init		= (void *)mptcp_sched_rr_init,
	.release	= (void *)mptcp_sched_rr_release,
	.data_init	= (void *)bpf_rr_data_init,
	.get_subflow	= (void *)bpf_rr_get_subflow,
	.name		= "bpf_rr",
};