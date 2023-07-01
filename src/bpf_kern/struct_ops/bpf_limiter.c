
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} timmer SEC(".maps");

#define MAX_TOKEN 100

#define MPTCP_SUBFLOWS_MAX 8

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;
extern void mptcp_sched_data_set_contexts(const struct mptcp_sock *msk,
					  struct mptcp_sched_data *data) __ksym;

extern bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;

extern long mptcp_timeout_from_subflow(const struct mptcp_subflow_context *subflow) __ksym;

extern void mptcp_set_timeout(struct sock *sk) __ksym;

extern bool mptcp_subflow_stream_memory_free(const struct mptcp_subflow_context *subflow) __ksym;

SEC("struct_ops/mptcp_sched_limiter_init")
void BPF_PROG(mptcp_sched_limiter_init, const struct mptcp_sock *msk)
{
        
}

SEC("struct_ops/mptcp_sched_limiter_release")
void BPF_PROG(mptcp_sched_limiter_release, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/bpf_limiter_data_init")
void BPF_PROG(bpf_limiter_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
        mptcp_sched_data_set_contexts(msk, data);
}

SEC("struct_ops/bpf_limiter_get_subflowmm")
int BPF_PROG(bpf_limiter_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	u64 *last_snd;
        u64 now = bpf_ktime_get_ns();
        int key = 0;
        last_snd = bpf_map_lookup_elem(&timmer, &key);
        if (last_snd == NULL) {
                bpf_printk("bug: not found key 0");
                mptcp_subflow_set_scheduled(data->contexts[0], true);
                return 0;
        }
        if (*last_snd == 0) {
                *last_snd = now; 
                mptcp_subflow_set_scheduled(data->contexts[0], true);
                return 0;
        } else if (now - *last_snd >= 100000) {
                mptcp_subflow_set_scheduled(data->contexts[0], true);
                *last_snd = now; 
                return 0;
        } else {
                return -1;
        }
}

SEC(".struct_ops")
struct mptcp_sched_ops limiter = {
	.init		= (void *)mptcp_sched_limiter_init,
	.release	= (void *)mptcp_sched_limiter_release,
	.data_init	= (void *)bpf_limiter_data_init,
	.get_subflow	= (void *)bpf_limiter_get_subflow,
	.name		= "bpf_limiter",
};