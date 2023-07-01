#include "mptcp_sched.h"
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "mptcp_sched_map_def.h"
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

#define MPTCP_SUBFLOWS_MAX 8

struct subflow_metric_data {
        unsigned long sk_pacing_rate;
        int sk_wmem_queued;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct subflow_metric_data);
	__uint(max_entries, 10000);
        __uint(pinning, 1);
} subflow_metric SEC(".maps");

static __always_inline void record_metrics(struct sock *ssk) 
{
        int res;
        u64 key = (u64)ssk;
        struct subflow_metric_data metric;
        metric.sk_pacing_rate = ssk->sk_pacing_rate;
        metric.sk_wmem_queued = ssk->sk_wmem_queued;
        //local_ip = bpf_ntohl(ssk->__sk_common.skc_rcv_saddr);
        //remote_ip = bpf_ntohl(ssk->__sk_common.skc_daddr);
        res = bpf_map_update_elem(&subflow_metric, &key, &metric, 0);
        if (res <  0) {
                bpf_printk("bug: failed to update subflow matric %d", res);
        }
}

extern void mptcp_subflow_set_scheduled(struct mptcp_subflow_context *subflow,
					bool scheduled) __ksym;
extern void mptcp_sched_data_set_contexts(const struct mptcp_sock *msk,
					  struct mptcp_sched_data *data) __ksym;

extern bool mptcp_subflow_active(struct mptcp_subflow_context *subflow) __ksym;

extern long mptcp_timeout_from_subflow(const struct mptcp_subflow_context *subflow) __ksym;

extern bool mptcp_subflow_stream_memory_free(const struct mptcp_subflow_context *subflow) __ksym;

extern void mptcp_set_timeout(struct sock *sk) __ksym;

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

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y; })

SEC("struct_ops/bpf_emptcp_get_subflow")
int BPF_PROG(bpf_emptcp_get_subflow, struct mptcp_sock *msk,
		   struct mptcp_sched_data *data)
{
        u64 key = msk->local_key;
        bool scheduled = false;
        long tout = 0;
        struct emptcp_sched_policy *policy;
        policy = bpf_map_lookup_elem(&mptcp_sched_policies, &key);
        if (policy == NULL) {
                fallback_policy(msk, data);
                scheduled = true;
                goto out;
        }
        int i;
        for (i = 0; i < MPTCP_SUBFLOWS_MAX; i++) {
                if (data->contexts[i] == NULL) {
                        break;
                }
                if (policy->subflows[i].sk != data->contexts[i]->tcp_sock) {
                        fallback_policy(msk, data);
                        scheduled = true;
                        goto out;
                }
                /* TODO: set timeout*/
                record_metrics(data->contexts[i]->tcp_sock);
                struct mptcp_subflow_context *subflow = data->contexts[i];
                tout = max(tout, mptcp_timeout_from_subflow(subflow));
                //bpf_printk("debug: sched subflow, index: %d,  sk: %x, tcp_sock: %x\n", i, policy->subflows[i].sk, data->contexts[i]->tcp_sock);
                if (policy->subflows[i].scheduled) {
                        mptcp_subflow_set_scheduled(data->contexts[i], 1);
                        scheduled = true;
                }       
        } 

out:;
        msk->timer_ival = tout > 0 ? tout : 50;
        int flag = 1; 
        bpf_map_update_elem(&mptcp_sched_flags, &key, &flag, BPF_ANY);
        //bpf_printk("emptcp sched: %d, tout: %d", scheduled, tout);
        if (scheduled) {
                return 0;
        } else {
                return -1;
        }
}

SEC(".struct_ops")
struct mptcp_sched_ops emptcp_sc = {
	.init		= (void *)mptcp_sched_emptcp_init,
	.release	= (void *)mptcp_sched_emptcp_release,
	.data_init	= (void *)bpf_emptcp_data_init,
	.get_subflow	= (void *)bpf_emptcp_get_subflow,
	.name		= "bpf_emptcp_scv2",
};