#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 2);
} credits SEC(".maps");

#define MPTCP_SUBFLOWS_MAX 8

#define CREDIT_SLOT 0 
#define TIME_SLOT 1
#define INIT_CREDIT 100
#define CREDIT_RATE_PER_SEC 1000

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;
extern void mptcp_sched_data_set_contexts(const struct mptcp_sock *msk,
					  struct mptcp_sched_data *data) __ksym;

extern bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;

extern long mptcp_timeout_from_subflow(const struct mptcp_subflow_context *subflow) __ksym;

extern void mptcp_set_timeout(struct sock *sk) __ksym;

extern bool mptcp_subflow_stream_memory_free(const struct mptcp_subflow_context *subflow) __ksym;

SEC("struct_ops/mptcp_sched_credit_init")
void BPF_PROG(mptcp_sched_credit_init, const struct mptcp_sock *msk)
{
        int key_credit = CREDIT_SLOT;
        int key_time = TIME_SLOT;
        u64 now = bpf_ktime_get_ns();
        u64 init_credit = INIT_CREDIT;
        bpf_map_update_elem(&credits, &key_credit, &init_credit, 0);
        bpf_map_update_elem(&credits, &key_time, &now, 0);
}

SEC("struct_ops/mptcp_sched_credit_release")
void BPF_PROG(mptcp_sched_credit_release, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/bpf_credit_data_init")
void BPF_PROG(bpf_credit_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
        mptcp_sched_data_set_contexts(msk, data);
}

SEC("struct_ops/bpf_credit_get_subflowmm")
int BPF_PROG(bpf_credit_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
	int key_credit = CREDIT_SLOT;
        int key_time = TIME_SLOT;
        u64 *credit_left = bpf_map_lookup_elem(&credits, &key_credit);
        if (credit_left == NULL) {
                bpf_printk("debug: faild to get credit \n");
                mptcp_subflow_set_scheduled(data->contexts[0], true);
                return 0;
        }
        if (*credit_left > 0) {
                //still have credits
                *credit_left -= 1;
                mptcp_subflow_set_scheduled(data->contexts[0], true);
                return 0;
        }
        //no credits geneterate
        u64 *last_time = bpf_map_lookup_elem(&credits, &key_time);
        if (last_time == NULL) {
                bpf_printk("debug: faild to get time \n");
                mptcp_subflow_set_scheduled(data->contexts[0], true);
                return 0;
        }
        u64 now = bpf_ktime_get_ns();
        u64 duration= (now - *last_time) / 1000000000;
        *credit_left = duration * CREDIT_RATE_PER_SEC;
        if (*credit_left > 0) {
                *last_time = now;
        }
        return -1;
}

SEC(".struct_ops")
struct mptcp_sched_ops credit = {
	.init		= (void *)mptcp_sched_credit_init,
	.release	= (void *)mptcp_sched_credit_release,
	.data_init	= (void *)bpf_credit_data_init,
	.get_subflow	= (void *)bpf_credit_get_subflow,
	.name		= "bpf_credit",
};