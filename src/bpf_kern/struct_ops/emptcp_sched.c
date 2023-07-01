#include "mptcp_sched.h"
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "mptcp_sched_map_def.h"

char _license[] SEC("license") = "GPL";

#define MPTCP_SUBFLOWS_MAX 8

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;
extern void mptcp_sched_data_set_contexts(const struct mptcp_sock *msk,
					  struct mptcp_sched_data *data) __ksym;

SEC("struct_ops/mptcp_sched_emptcp_init")
void BPF_PROG(mptcp_sched_emptcp_init, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/mptcp_sched_emptcp_release")
void BPF_PROG(mptcp_sched_emptcp_release, const struct mptcp_sock *msk)
{
}

SEC("struct_ops/bpf_emptcp_data_init")
void BPF_PROG(bpf_emptcp_data_init, const struct mptcp_sock *msk,
		    struct mptcp_sched_data *data)
{
        mptcp_sched_data_set_contexts(msk, data);
}

/*always choose the first subflow*/
static __always_inline void fallback_policy(const struct mptcp_sock *msk, 
                                            struct mptcp_sched_data *data)
{
        mptcp_subflow_set_scheduled(data->contexts[0], 1);
}

SEC("struct_ops/bpf_emptcp_get_subflow")
int BPF_PROG(bpf_emptcp_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
        u64 key = msk->local_key;
        bool scheduled = false;
        struct emptcp_sched_policy *policy;
        policy = bpf_map_lookup_elem(&mptcp_sched_policies, &key);
        if (policy == NULL) {
                fallback_policy(msk, data);
                goto out;
        }
        int i;
        for (i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
                if (policy->subflows[i].sk != data->contexts[i]->tcp_sock) {
                       bpf_printk("warn: bad emptcp sched policy, subflow sock inconsistance, index: %d,  sk: %x, tcp_sock: %x\n", i, policy->subflows[i].sk, data->contexts[i]->tcp_sock);
                       break;
                }
                //bpf_printk("debug: sched subflow, index: %d,  sk: %x, tcp_sock: %x\n", i, policy->subflows[i].sk, data->contexts[i]->tcp_sock);
                if (policy->subflows[i].scheduled) {
                        mptcp_subflow_set_scheduled(data->contexts[i], 1);
                        scheduled = true;
                }       
        } 
        if (!scheduled) {
                bpf_printk("warn: policy not sched, fallback index %d", i);
                fallback_policy(msk, data);
        }
out:;
        int flag = 1; 
        bpf_map_update_elem(&mptcp_sched_flags, &key, &flag, BPF_ANY);
        return 0;
}

SEC(".struct_ops")
struct mptcp_sched_ops emptcp_sc = {
	.init		= (void *)mptcp_sched_emptcp_init,
	.release	= (void *)mptcp_sched_emptcp_release,
	.data_init	= (void *)bpf_emptcp_data_init,
	.get_subflow	= (void *)bpf_emptcp_get_subflow,
	.name		= "bpf_emptcp_sc",
};